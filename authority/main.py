from __future__ import annotations

import base64
import json
import os
import uuid
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .attack_detector import AttackDetector
from .key_manager import KeyManager
from .storage import InMemoryStorage

from crypto import aes, kdf, shamir
from crypto.utils import best_effort_wipe, random_bytes
from storage.minio_adapter import StorageError, upload_object


app = FastAPI(title="Authority Service", version="1.0")

_storage = InMemoryStorage()
_key_manager = KeyManager(storage=_storage)
_attack_detector = AttackDetector(key_manager=_key_manager, storage=_storage)


def _b64e(data: bytes) -> str:
	return base64.b64encode(data).decode("ascii")


def _context_for_kdf(*, client_id: str, nonce: bytes) -> bytes:
	return client_id.encode("utf-8") + b"|" + bytes(nonce)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
	"""Health check endpoint. Does not touch key state."""
	return {"status": "ok"}

@app.get("/health")
async def health() -> dict[str, str]:
	return {"status": "ok"}


class RegisterKeyRequest(BaseModel):
	key_id: str = Field(..., min_length=1)
	client_id: str = Field(..., min_length=1)
	authority_share_b64: str = Field(..., min_length=1)
	expires_in_seconds: int = Field(..., gt=0, le=60 * 60 * 24 * 365)
	nonce: str = Field(..., min_length=1)


class RegisterKeyResponse(BaseModel):
	status: str


class RequestShareRequest(BaseModel):
	key_id: str = Field(..., min_length=1)
	client_id: str = Field(..., min_length=1)
	nonce: str = Field(..., min_length=1)


class RequestShareResponse(BaseModel):
	status: str
	authority_share_b64: str | None = None
	denial_reason: str | None = None
	key_status: str | None = None


class DestroyKeyRequest(BaseModel):
	key_id: str = Field(..., min_length=1)
	client_id: str = Field(..., min_length=1)
	nonce: str = Field(..., min_length=1)
	reason: str | None = None


class DestroyKeyResponse(BaseModel):
	status: str
	destroyed: bool
	key_status: str


class CreateDemoSessionResponse(BaseModel):
	key_id: str
	object_id: str
	client_id: str
	client_share: str


@app.post("/create_demo_session", response_model=CreateDemoSessionResponse)
async def create_demo_session() -> CreateDemoSessionResponse:
	"""Create a minimal end-to-end demo session.

	Security notes:
	- Authority generates the master key but never reconstructs it from shares.
	- Only the authority share is persisted in memory (ACTIVE lifecycle enforced by KeyManager).
	- Plaintext is never logged.
	"""
	key_id = f"demo-key-{uuid.uuid4()}"
	object_id = f"demo-object-{uuid.uuid4()}"
	client_id = f"client-{uuid.uuid4()}"

	# Demo plaintext: generated server-side; never logged.
	plaintext_buf = bytearray(b"Confidential: live demo object (encrypted client-side)")

	master_key = aes.generate_key()
	master_key_buf = bytearray(master_key)
	derived_key_buf: bytearray | None = None
	registered = False
	try:
		shares = shamir.split(master_key, t=2, n=3)
		client_share = shares[0]
		authority_share = shares[1]
		unused_share = shares[2]
		best_effort_wipe(bytearray(unused_share))

		expires_default = 24 * 60 * 60
		try:
			expires_in_seconds = int(os.getenv("DEMO_EXPIRES_IN_SECONDS", str(expires_default)))
		except Exception:
			expires_in_seconds = expires_default
		_key_manager.register_key(
			key_id=key_id,
			client_id=client_id,
			authority_share=authority_share,
			expires_in_seconds=expires_in_seconds,
		)
		registered = True

		kdf_nonce = random_bytes(16)
		derived_key = kdf.derive(master_key, context=_context_for_kdf(client_id=client_id, nonce=kdf_nonce))
		derived_key_buf = bytearray(derived_key)

		enc = aes.encrypt(bytes(plaintext_buf), key=derived_key)
		envelope = {
			"key_id": key_id,
			"client_id": client_id,
			"kdf_nonce_b64": _b64e(kdf_nonce),
			"aes": enc,
		}
		blob = json.dumps(envelope).encode("utf-8")
		try:
			upload_object(object_id, blob)
		except StorageError as exc:
			# Avoid leaving a usable key share behind if storage failed.
			if registered:
				try:
					_key_manager.destroy_key(key_id, reason="storage_upload_failed")
				except Exception:
					pass
			raise HTTPException(status_code=503, detail=str(exc)) from exc

		return CreateDemoSessionResponse(
			key_id=key_id,
			object_id=object_id,
			client_id=client_id,
			client_share=_b64e(client_share),
		)
	finally:
		best_effort_wipe(master_key_buf)
		best_effort_wipe(derived_key_buf)
		best_effort_wipe(plaintext_buf)


@app.post("/register_key", response_model=RegisterKeyResponse)
async def register_key(body: RegisterKeyRequest) -> RegisterKeyResponse:
	# Guard also enforces nonce replay protection and parallel request detection.
	async with _attack_detector.guard_request(
		key_id=body.key_id,
		client_id=body.client_id,
		nonce=body.nonce,
	):
		try:
			share = _key_manager.decode_share_b64(body.authority_share_b64)
			_key_manager.register_key(
				key_id=body.key_id,
				client_id=body.client_id,
				authority_share=share,
				expires_in_seconds=body.expires_in_seconds,
			)
		except ValueError as exc:
			raise HTTPException(status_code=400, detail=str(exc)) from exc

	return RegisterKeyResponse(status="ok")


@app.post("/request_share", response_model=RequestShareResponse)
async def request_share(body: RequestShareRequest) -> RequestShareResponse:
	async with _attack_detector.guard_request(
		key_id=body.key_id,
		client_id=body.client_id,
		nonce=body.nonce,
	):
		allowed, share, denial = _key_manager.request_share(key_id=body.key_id, client_id=body.client_id)
		key_status = _key_manager.get_key_status(body.key_id)
		if not allowed or share is None:
			denial_reason = "revoked" if key_status in {"DESTROYED", "EXPIRED"} else denial
			return RequestShareResponse(
				status="denied",
				authority_share_b64=None,
				denial_reason=denial_reason,
				key_status=key_status,
			)

		return RequestShareResponse(
			status="ok",
			authority_share_b64=_key_manager.encode_share_b64(share),
			denial_reason=None,
			key_status=key_status,
		)


@app.post("/destroy_key", response_model=DestroyKeyResponse)
async def destroy_key(body: DestroyKeyRequest) -> DestroyKeyResponse:
	async with _attack_detector.guard_request(
		key_id=body.key_id,
		client_id=body.client_id,
		nonce=body.nonce,
	):
		destroyed = _key_manager.destroy_key(body.key_id, reason=body.reason or "client_requested")
		return DestroyKeyResponse(status="ok", destroyed=destroyed, key_status=_key_manager.get_key_status(body.key_id))

