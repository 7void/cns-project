from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, List, Optional


def _utcnow() -> datetime:
	return datetime.now(timezone.utc)


@dataclass(frozen=True)
class AuditEvent:
	timestamp: datetime
	event_type: str
	key_id: Optional[str]
	client_id: Optional[str]
	details: Dict[str, Any]


class InMemoryStorage:
	"""In-memory placeholder persistence for key metadata and audit logs.

	This intentionally does not store full encryption keys. It can store key IDs,
	client IDs, timestamps, and state transitions.
	"""

	def __init__(self) -> None:
		self._lock = RLock()
		self._key_metadata: Dict[str, Dict[str, Any]] = {}
		self._audit_log: List[AuditEvent] = []

	def upsert_key_metadata(self, key_id: str, metadata: Dict[str, Any]) -> None:
		with self._lock:
			existing = self._key_metadata.get(key_id, {})
			merged = {**existing, **metadata}
			self._key_metadata[key_id] = merged

	def get_key_metadata(self, key_id: str) -> Dict[str, Any]:
		with self._lock:
			return dict(self._key_metadata.get(key_id, {}))

	def append_audit_event(
		self,
		*,
		event_type: str,
		key_id: Optional[str] = None,
		client_id: Optional[str] = None,
		details: Optional[Dict[str, Any]] = None,
	) -> None:
		event = AuditEvent(
			timestamp=_utcnow(),
			event_type=event_type,
			key_id=key_id,
			client_id=client_id,
			details=details or {},
		)
		with self._lock:
			self._audit_log.append(event)

	def list_audit_events(self) -> List[AuditEvent]:
		with self._lock:
			return list(self._audit_log)

