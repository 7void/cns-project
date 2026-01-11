from __future__ import annotations

import base64
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .utils import generate_nonce


def _b64e(data: bytes) -> str:
	return base64.b64encode(data).decode("ascii")


def _b64d(data_b64: str) -> bytes:
	return base64.b64decode(data_b64, validate=True)


def generate_key() -> bytes:
	"""Generate a fresh AES-256 key."""
	return AESGCM.generate_key(bit_length=256)


def encrypt(data: bytes, key: bytes) -> Dict[str, Any]:
	"""Encrypt data using AES-256-GCM.

	Returns a JSON-serializable payload containing base64 fields.
	"""
	if not isinstance(data, (bytes, bytearray)):
		raise TypeError("data must be bytes")
	if not isinstance(key, (bytes, bytearray)):
		raise TypeError("key must be bytes")
	if len(key) != 32:
		raise ValueError("key must be 32 bytes (AES-256)")

	nonce = generate_nonce(12)
	aesgcm = AESGCM(bytes(key))
	aad: Optional[bytes] = b""
	ct = aesgcm.encrypt(nonce=nonce, data=bytes(data), associated_data=aad)
	return {
		"alg": "AES-256-GCM",
		"nonce_b64": _b64e(nonce),
		"ciphertext_b64": _b64e(ct),
		"aad_b64": _b64e(aad) if aad is not None else None,
	}


def decrypt(payload: Dict[str, Any], key: bytes) -> bytes:
	"""Decrypt AES-256-GCM payload.

	Raises ValueError on tampering, invalid tags, or malformed payloads.
	"""
	if not isinstance(payload, dict):
		raise TypeError("payload must be a dict")
	if not isinstance(key, (bytes, bytearray)):
		raise TypeError("key must be bytes")
	if len(key) != 32:
		raise ValueError("key must be 32 bytes (AES-256)")

	try:
		nonce_b64 = payload["nonce_b64"]
		ciphertext_b64 = payload["ciphertext_b64"]
		aad_b64 = payload.get("aad_b64")
		nonce = _b64d(nonce_b64)
		ct = _b64d(ciphertext_b64)
		aad = _b64d(aad_b64) if isinstance(aad_b64, str) else b""
	except Exception as exc:  # noqa: BLE001
		raise ValueError("malformed payload") from exc

	if len(nonce) != 12:
		raise ValueError("invalid nonce length")

	aesgcm = AESGCM(bytes(key))
	try:
		return aesgcm.decrypt(nonce=nonce, data=ct, associated_data=aad)
	except InvalidTag as exc:
		raise ValueError("authentication failed (tampering or wrong key)") from exc

