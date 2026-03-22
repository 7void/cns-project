from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import List, Optional


logger = logging.getLogger(__name__)


@dataclass
class ForensicEvent:
    """A single recorded access during a POISONED key's forensic window."""

    timestamp: datetime
    key_id: str
    client_id: Optional[str]
    ip_address: Optional[str]
    nonce: Optional[str]


class ForensicLogger:
    """Records every /request_share access observed while a key is in POISONED state.

    All data is held in memory only. Events are appended per key_id so that
    operators can query the full access history for a specific compromised key.
    """

    def __init__(self) -> None:
        self._lock: RLock = RLock()
        self._events: dict[str, List[ForensicEvent]] = {}

    def record(
        self,
        *,
        key_id: str,
        client_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> None:
        """Record a share-access event for a POISONED key."""
        event = ForensicEvent(
            timestamp=datetime.now(timezone.utc),
            key_id=key_id,
            client_id=client_id,
            ip_address=ip_address,
            nonce=nonce,
        )
        with self._lock:
            self._events.setdefault(key_id, []).append(event)

        count = self.get_request_count(key_id)
        logger.warning(
            "FORENSIC LOG [POISONED key] key_id=%s client_id=%s ip=%s nonce=%s "
            "| total accesses during window: %d",
            key_id,
            client_id,
            ip_address,
            nonce,
            count,
        )

    def get_events(self, key_id: str) -> List[ForensicEvent]:
        """Return all forensic events recorded for the given key_id."""
        with self._lock:
            return list(self._events.get(key_id, []))

    def get_request_count(self, key_id: str) -> int:
        """Return the number of share-access attempts recorded for key_id."""
        with self._lock:
            return len(self._events.get(key_id, []))
