from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .attack_detector import AttackDetector
from .key_manager import KeyManager
from .storage import InMemoryStorage
from .vault_state import VaultState

from crypto import aes, kdf, shamir
from crypto.utils import best_effort_wipe, random_bytes
from storage.minio_adapter import StorageError, upload_object


app = FastAPI(title="Authority Service", version="1.0")

_storage = InMemoryStorage()
_key_manager = KeyManager(storage=_storage)
_attack_detector = AttackDetector(key_manager=_key_manager, storage=_storage)
_vault = VaultState()


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


class LatestKeyResponse(BaseModel):
	key_id: str | None = None
	client_id: str | None = None
	key_status: str | None = None


@app.get("/latest_key", response_model=LatestKeyResponse)
async def latest_key() -> LatestKeyResponse:
	"""Return the most recently registered key_id (best-effort).

	Intended for demo/operator UIs. Returns only identifiers + lifecycle status.
	"""
	try:
		events = _storage.list_audit_events()
	except Exception:
		events = []

	latest = None
	for ev in reversed(events):
		if ev.event_type == "key_registered" and ev.key_id:
			latest = ev
			break

	if latest is None:
		return LatestKeyResponse(key_id=None, client_id=None, key_status=None)

	key_id = str(latest.key_id)
	return LatestKeyResponse(
		key_id=key_id,
		client_id=str(latest.client_id) if latest.client_id else None,
		key_status=_key_manager.get_key_status(key_id),
	)


class RegisterKeyResponse(BaseModel):
	status: str


class RequestShareRequest(BaseModel):
	key_id: str = Field(..., min_length=1)
	client_id: str = Field(..., min_length=1)
	file_id: str | None = None
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


class RegisterClientRequest(BaseModel):
	name: str = Field(..., min_length=1)
	password: str = Field(..., min_length=1)


class RegisterClientResponse(BaseModel):
	client_id: str
	name: str
	registered_at: str


class LoginRequest(BaseModel):
	name: str = Field(..., min_length=1)
	password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
	client_id: str
	name: str

class ClientListResponse(BaseModel):
	client_id: str
	name: str


class RegisterFileRequest(BaseModel):
	filename: str = Field(..., min_length=1)
	uploader_id: str = Field(..., min_length=1)
	authorized_clients: list[str]
	key_id: str = Field(..., min_length=1)
	object_id: str = Field(..., min_length=1)
	authority_share_b64: str = Field(..., min_length=1)
	expires_in_seconds: int | None = Field(default=None, gt=0, le=60 * 60 * 24 * 365)


class RegisterFileResponse(BaseModel):
	file_id: str
	status: str
	created_at: str


class FileRecordResponse(BaseModel):
	file_id: str
	filename: str
	uploader_id: str
	authorized_clients: list[str]
	object_id: str
	key_id: str
	created_at: str
	status: str


class AccessLogResponse(BaseModel):
	timestamp: str
	client_id: str
	file_id: str
	result: str
	reason: str


class MetricsResponse(BaseModel):
	total_files: int
	active_files: int
	destroyed_files: int
	expired_files: int
	total_access_requests: int
	denied_requests: int


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


@app.post("/register_client", response_model=RegisterClientResponse)
async def register_client(body: RegisterClientRequest) -> RegisterClientResponse:
	try:
		client = _vault.register_client(name=body.name, password=body.password)
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc
	return RegisterClientResponse(client_id=client.client_id, name=client.name, registered_at=client.registered_at.isoformat())


@app.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest) -> LoginResponse:
	try:
		client = _vault.login(name=body.name, password=body.password)
	except ValueError as exc:
		raise HTTPException(status_code=401, detail=str(exc)) from exc
	return LoginResponse(client_id=client.client_id, name=client.name)


@app.get("/clients", response_model=list[ClientListResponse])
async def list_clients() -> list[ClientListResponse]:
	clients = _vault.list_clients()
	return [ClientListResponse(client_id=c.client_id, name=c.name) for c in clients]


@app.post("/register_file", response_model=RegisterFileResponse)
async def register_file(body: RegisterFileRequest) -> RegisterFileResponse:
	# Client uploads encrypted object to MinIO; authority stores metadata + its Shamir share.
	try:
		authorized_clients = [c.strip() for c in (body.authorized_clients or []) if c and c.strip()]
		if not authorized_clients:
			raise ValueError("authorized_clients must be non-empty")
		if body.uploader_id not in authorized_clients:
			authorized_clients = [body.uploader_id, *authorized_clients]

		authority_share = _key_manager.decode_share_b64(body.authority_share_b64)
		expires_default = 24 * 60 * 60
		expires_in_seconds = int(body.expires_in_seconds or int(os.getenv("DEMO_EXPIRES_IN_SECONDS", str(expires_default))))
		_key_manager.register_key(
			key_id=body.key_id,
			client_id=body.uploader_id,
			authority_share=authority_share,
			expires_in_seconds=expires_in_seconds,
		)
		file_id = f"file-{uuid.uuid4()}"
		record = _vault.register_file(
			file_id=file_id,
			filename=body.filename,
			uploader_id=body.uploader_id,
			authorized_clients=authorized_clients,
			object_id=body.object_id,
			key_id=body.key_id,
			status="ACTIVE",
		)
		_storage.append_audit_event(
			event_type="file_registered",
			key_id=body.key_id,
			client_id=body.uploader_id,
			details={"file_id": record.file_id, "filename": record.filename, "object_id": record.object_id},
		)
		return RegisterFileResponse(file_id=record.file_id, status=record.status, created_at=record.created_at.isoformat())
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/files", response_model=list[FileRecordResponse])
async def list_files(client_id: str | None = None) -> list[FileRecordResponse]:
	files = _vault.list_files()
	if client_id:
		files = [f for f in files if client_id in f.authorized_clients]
	return [
		FileRecordResponse(
			file_id=f.file_id,
			filename=f.filename,
			uploader_id=f.uploader_id,
			authorized_clients=list(f.authorized_clients),
			object_id=f.object_id,
			key_id=f.key_id,
			created_at=f.created_at.isoformat(),
			status=f.status,
		)
		for f in files
	]


@app.get("/logs", response_model=list[AccessLogResponse])
async def list_logs() -> list[AccessLogResponse]:
	logs = _vault.list_access_logs()
	return [
		AccessLogResponse(
			timestamp=l.timestamp.isoformat(),
			client_id=l.client_id,
			file_id=l.file_id,
			result=l.result,
			reason=l.reason,
		)
		for l in logs
	]


@app.get("/metrics", response_model=MetricsResponse)
async def metrics() -> MetricsResponse:
	m = _vault.metrics()
	return MetricsResponse(
		total_files=m.total_files,
		active_files=m.active_files,
		destroyed_files=m.destroyed_files,
		expired_files=m.expired_files,
		total_access_requests=m.total_access_requests,
		denied_requests=m.denied_requests,
	)


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
	# Guard for nonce replay protection; access control is enforced below.
	async with _attack_detector.guard_request(key_id=body.key_id, client_id=body.client_id, nonce=body.nonce):
		file_id = (body.file_id or "").strip()
		if file_id:
			record = _vault.get_file(file_id)
			if record is None:
				_vault.log_access(client_id=body.client_id, file_id=file_id, result="DENIED", reason="unknown_file")
				return RequestShareResponse(status="denied", authority_share_b64=None, denial_reason="unknown_file", key_status="UNKNOWN")
			if record.key_id != body.key_id:
				_vault.log_access(client_id=body.client_id, file_id=file_id, result="DENIED", reason="key_mismatch")
				return RequestShareResponse(status="denied", authority_share_b64=None, denial_reason="key_mismatch", key_status=_key_manager.get_key_status(body.key_id))
			if body.client_id not in record.authorized_clients:
				_vault.log_access(client_id=body.client_id, file_id=file_id, result="DENIED", reason="not_authorized")
				return RequestShareResponse(status="denied", authority_share_b64=None, denial_reason="not_authorized", key_status=_key_manager.get_key_status(body.key_id))

		allowed, share, denial = _key_manager.request_share(key_id=body.key_id, client_id=body.client_id)
		key_status = _key_manager.get_key_status(body.key_id)
		if file_id:
			# Keep file status aligned with key lifecycle for dashboards.
			if key_status in {"DESTROYED", "EXPIRED"}:
				_vault.set_file_status_by_key_id(key_id=body.key_id, status=key_status)

		if not allowed or share is None:
			denial_reason = "revoked" if key_status in {"DESTROYED", "EXPIRED"} else denial
			if file_id:
				_vault.log_access(client_id=body.client_id, file_id=file_id, result="DENIED", reason=denial_reason)
			return RequestShareResponse(status="denied", authority_share_b64=None, denial_reason=denial_reason, key_status=key_status)

		if file_id:
			_vault.log_access(client_id=body.client_id, file_id=file_id, result="SUCCESS", reason="ok")
		return RequestShareResponse(status="ok", authority_share_b64=_key_manager.encode_share_b64(share), denial_reason=None, key_status=key_status)


@app.post("/destroy_key", response_model=DestroyKeyResponse)
async def destroy_key(body: DestroyKeyRequest) -> DestroyKeyResponse:
	async with _attack_detector.guard_request(
		key_id=body.key_id,
		client_id=body.client_id,
		nonce=body.nonce,
	):
		destroyed = _key_manager.destroy_key(body.key_id, reason=body.reason or "client_requested")
		if destroyed:
			_vault.set_file_status_by_key_id(key_id=body.key_id, status="DESTROYED")
		return DestroyKeyResponse(status="ok", destroyed=destroyed, key_status=_key_manager.get_key_status(body.key_id))

