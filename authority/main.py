from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .attack_detector import AttackDetector
from .key_manager import KeyManager
from .storage import InMemoryStorage


app = FastAPI(title="Authority Service", version="1.0")

_storage = InMemoryStorage()
_key_manager = KeyManager(storage=_storage)
_attack_detector = AttackDetector(key_manager=_key_manager, storage=_storage)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
	"""Health check endpoint. Does not touch key state."""
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

