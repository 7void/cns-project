from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive(master_key: bytes, context: bytes) -> bytes:
	"""Derive a 32-byte key from `master_key`, bound to `context`.

	Uses HKDF-SHA256.
	"""
	if not isinstance(master_key, (bytes, bytearray)):
		raise TypeError("master_key must be bytes")
	if len(master_key) != 32:
		raise ValueError("master_key must be 32 bytes (AES-256)")
	if not isinstance(context, (bytes, bytearray)):
		raise TypeError("context must be bytes")
	if len(context) == 0:
		raise ValueError("context must be non-empty")

	hkdf = HKDF(
		algorithm=hashes.SHA256(),
		length=32,
		salt=None,
		info=bytes(context),
	)
	return hkdf.derive(bytes(master_key))

