from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import RLock
from typing import Optional, Tuple

from .storage import InMemoryStorage
from crypto.utils import best_effort_wipe


def _utcnow() -> datetime:
	return datetime.now(timezone.utc)


@dataclass
class KeyRecord:
	key_id: str
	registered_client_id: str
	share: Optional[bytearray]
	expires_at: datetime
	status: "KeyStatus"
	terminal_at: Optional[datetime]
	terminal_reason: Optional[str]
	terminal_event_type: Optional[str]


class KeyStatus(str, Enum):
	ACTIVE = "ACTIVE"
	DESTROYED = "DESTROYED"
	EXPIRED = "EXPIRED"


class KeyManager:
	"""Tracks and irreversibly destroys authority-held key shares.

	Security properties:
	- Once destroyed (manual or by expiry/violation), the share is overwritten and
	  must never be returned again.
	- Full AES keys are never stored here.
	"""

	def __init__(self, storage: InMemoryStorage) -> None:
		self._storage = storage
		self._lock = RLock()
		self._records: dict[str, KeyRecord] = {}

	def get_key_status(self, key_id: str) -> str:
		with self._lock:
			record = self._records.get(key_id)
			if record is None:
				return "UNKNOWN"
			return record.status.value

	def register_key(
		self,
		*,
		key_id: str,
		client_id: str,
		authority_share: bytes,
		expires_in_seconds: int,
	) -> None:
		if not key_id:
			raise ValueError("key_id is required")
		if not client_id:
			raise ValueError("client_id is required")
		if not isinstance(authority_share, (bytes, bytearray)) or len(authority_share) == 0:
			raise ValueError("authority_share must be non-empty bytes")
		if expires_in_seconds <= 0:
			raise ValueError("expires_in_seconds must be > 0")

		expires_at = _utcnow() + timedelta(seconds=int(expires_in_seconds))
		share_copy = bytearray(bytes(authority_share))

		with self._lock:
			existing = self._records.get(key_id)
			if existing is not None:
				# Strict state machine: terminal states cannot be re-registered.
				if existing.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
					raise ValueError(f"key_id '{key_id}' is terminal ({existing.status.value})")
				# Also refuse overwriting ACTIVE keys to keep transitions explicit and deterministic.
				raise ValueError(f"key_id '{key_id}' already registered")

			self._records[key_id] = KeyRecord(
				key_id=key_id,
				registered_client_id=client_id,
				share=share_copy,
				expires_at=expires_at,
				status=KeyStatus.ACTIVE,
				terminal_at=None,
				terminal_reason=None,
				terminal_event_type=None,
			)

		self._storage.upsert_key_metadata(
			key_id,
			{
				"key_id": key_id,
				"registered_client_id": client_id,
				"expires_at": expires_at.isoformat(),
				"status": KeyStatus.ACTIVE.value,
			},
		)
		self._storage.append_audit_event(
			event_type="key_registered",
			key_id=key_id,
			client_id=client_id,
			details={"expires_at": expires_at.isoformat()},
		)

	def get_registered_client_id(self, key_id: str) -> Optional[str]:
		with self._lock:
			record = self._records.get(key_id)
			return record.registered_client_id if record else None

	def is_destroyed(self, key_id: str) -> bool:
		with self._lock:
			record = self._records.get(key_id)
			if record is None:
				return True
			return record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}

	def _terminalize_under_lock(self, key_id: str, *, status: KeyStatus, reason: str, event_type: str) -> bool:
		record = self._records.get(key_id)
		if record is None:
			return False
		if record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
			return False
		if status not in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
			raise ValueError("invalid terminal status")
		# Strict state machine: only ACTIVE can transition to terminal.
		if record.status != KeyStatus.ACTIVE:
			return False

		if record.share is not None:
			best_effort_wipe(record.share)
		record.share = None
		record.status = status
		record.terminal_at = _utcnow()
		record.terminal_reason = reason
		record.terminal_event_type = event_type

		self._storage.upsert_key_metadata(
			key_id,
			{
				"status": record.status.value,
				"terminal_at": record.terminal_at.isoformat() if record.terminal_at else None,
				"terminal_reason": reason,
			},
		)
		self._storage.append_audit_event(
			event_type=event_type,
			key_id=key_id,
			client_id=record.registered_client_id,
			details={"reason": reason, "key_status": record.status.value},
		)
		return True

	def destroy_key(self, key_id: str, *, reason: str) -> bool:
		if not key_id:
			raise ValueError("key_id is required")
		if not reason:
			reason = "unspecified"

		with self._lock:
			return self._terminalize_under_lock(key_id, status=KeyStatus.DESTROYED, reason=reason, event_type="key_destroyed")

	def _enforce_expiry_under_lock(self, record: KeyRecord) -> None:
		if record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
			return
		if _utcnow() >= record.expires_at:
			self._terminalize_under_lock(record.key_id, status=KeyStatus.EXPIRED, reason="expired", event_type="key_expired")

	def request_share(self, *, key_id: str, client_id: str) -> Tuple[bool, Optional[bytes], str]:
		"""Return (allowed, share_bytes, denial_reason)."""
		if not key_id:
			return False, None, "missing_key_id"
		if not client_id:
			return False, None, "missing_client_id"

		with self._lock:
			record = self._records.get(key_id)
			if record is None:
				return False, None, "unknown_key_id"

			self._enforce_expiry_under_lock(record)
			if record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
				return False, None, "revoked"

			if client_id != record.registered_client_id:
				return False, None, "client_id_mismatch"

			if record.share is None:
				# Invariant: ACTIVE keys must hold a share.
				return False, None, "revoked"

			share_bytes = bytes(record.share)

		self._storage.append_audit_event(
			event_type="share_released",
			key_id=key_id,
			client_id=client_id,
			details={"share_len": len(share_bytes)},
		)
		return True, share_bytes, "ok"

	@staticmethod
	def decode_share_b64(share_b64: str) -> bytes:
		if not share_b64:
			raise ValueError("share_b64 is required")
		try:
			return base64.b64decode(share_b64, validate=True)
		except Exception as exc:  # noqa: BLE001
			raise ValueError("invalid base64 share") from exc

	@staticmethod
	def encode_share_b64(share: bytes) -> str:
		return base64.b64encode(share).decode("ascii")

