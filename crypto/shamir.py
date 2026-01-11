from __future__ import annotations

from typing import List, Tuple

try:
	from Crypto.Protocol.SecretSharing import Shamir
except Exception as exc:  # noqa: BLE001
	Shamir = None  # type: ignore[assignment]
	_IMPORT_ERROR = exc


class ShamirError(Exception):
	"""Raised on Shamir split/combine failures."""


def _require_backend() -> None:
	if Shamir is None:
		raise ShamirError(
			"PyCryptodome is required for Shamir Secret Sharing. "
			"Install 'pycryptodome' in your environment."
		) from _IMPORT_ERROR


def _encode_share(index: int, share_bytes: bytes) -> bytes:
	if not (1 <= index <= 255):
		raise ShamirError("share index out of range")
	if not isinstance(share_bytes, (bytes, bytearray)) or len(share_bytes) == 0:
		raise ShamirError("invalid share bytes")
	return bytes([index]) + bytes(share_bytes)


def _decode_share(share: bytes) -> Tuple[int, bytes]:
	if not isinstance(share, (bytes, bytearray)):
		raise ShamirError("share must be bytes")
	raw = bytes(share)
	if len(raw) < 2:
		raise ShamirError("share too short")
	return raw[0], raw[1:]


def split(secret: bytes, t: int, n: int) -> List[bytes]:
	"""Split a secret into n shares with threshold t.

	Returns a list of binary shares. Shares are encoded as:
	  1 byte index || share_bytes
	"""
	_require_backend()
	if not isinstance(secret, (bytes, bytearray)):
		raise TypeError("secret must be bytes")
	if len(secret) == 0:
		raise ValueError("secret must be non-empty")
	if len(secret) % 16 != 0:
		raise ValueError("secret length must be a multiple of 16 bytes")
	if not (1 < t <= n <= 255):
		raise ValueError("require 1 < t <= n <= 255")

	try:
		blocks = [bytes(secret[i : i + 16]) for i in range(0, len(secret), 16)]
		per_block_shares = [Shamir.split(t, n, block) for block in blocks]  # type: ignore[union-attr]
	except Exception as exc:  # noqa: BLE001
		raise ShamirError("split failed") from exc

	# Merge shares across blocks by index.
	merged: dict[int, bytearray] = {}
	for block_shares in per_block_shares:
		for idx, share_bytes in block_shares:
			i = int(idx)
			merged.setdefault(i, bytearray()).extend(bytes(share_bytes))

	encoded: List[bytes] = []
	for idx in sorted(merged.keys()):
		encoded.append(_encode_share(idx, bytes(merged[idx])))
	return encoded


def combine(shares: List[bytes]) -> bytes:
	"""Combine shares to recover the original secret."""
	_require_backend()
	if not isinstance(shares, list) or len(shares) == 0:
		raise ValueError("shares must be a non-empty list")

	decoded = []
	for s in shares:
		idx, share_bytes = _decode_share(s)
		if len(share_bytes) % 16 != 0:
			raise ShamirError("invalid share length")
		decoded.append((idx, bytes(share_bytes)))

	blocks_count = len(decoded[0][1]) // 16
	if blocks_count == 0:
		raise ShamirError("invalid share payload")
	for _, payload in decoded:
		if len(payload) != blocks_count * 16:
			raise ShamirError("inconsistent share lengths")

	out = bytearray()
	try:
		for bi in range(blocks_count):
			part = []
			for idx, payload in decoded:
				part_bytes = payload[bi * 16 : (bi + 1) * 16]
				part.append((idx, part_bytes))
			out.extend(Shamir.combine(part))  # type: ignore[union-attr]
		return bytes(out)
	except Exception as exc:  # noqa: BLE001
		raise ShamirError("combine failed") from exc

