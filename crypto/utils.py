from __future__ import annotations

import hmac
import secrets
from typing import Optional, Union


def random_bytes(length: int) -> bytes:
	"""Return cryptographically secure random bytes."""
	if length <= 0:
		raise ValueError("length must be > 0")
	return secrets.token_bytes(length)


def generate_nonce(length: int = 12) -> bytes:
	"""Generate a nonce suitable for AES-GCM (12 bytes by default)."""
	return random_bytes(length)


def constant_time_equal(a: bytes, b: bytes) -> bool:
	"""Constant-time bytes comparison."""
	return hmac.compare_digest(a, b)


Wipeable = Union[bytearray, memoryview]


def best_effort_wipe(buf: Optional[Wipeable]) -> None:
	"""Best-effort in-place wipe of mutable buffers.

	Notes:
	- Python cannot reliably wipe immutable `bytes` objects.
	- This is a best-effort mitigation for lingering secrets in memory.
	"""
	if buf is None:
		return

	try:
		mv = buf if isinstance(buf, memoryview) else memoryview(buf)
		mv_cast = mv.cast("B")
		mv_cast[:] = b"\x00" * len(mv_cast)
	except Exception:
		# Best-effort only.
		return

