from __future__ import annotations

import base64
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import RLock
from typing import Optional, Tuple

from .storage import InMemoryStorage
from .forensic_log import ForensicLogger
from crypto.utils import best_effort_wipe


logger = logging.getLogger(__name__)


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
    POISONED = "POISONED"  # Canary tripwire triggered; share replaced with random bytes.


class KeyManager:
    """Tracks and irreversibly destroys authority-held key shares.

    Security properties:
    - Once destroyed (manual or by expiry/violation), the share is overwritten and
      must never be returned again.
    - Full AES keys are never stored here.
    - When a canary alert is received, the share is replaced with random bytes
      (POISONED) so that any attacker who reconstructs with it gets garbage.
      A 24-hour forensic window is opened; all access during that window is logged.
    """

    def __init__(self, storage: InMemoryStorage, forensic_logger: Optional[ForensicLogger] = None) -> None:
        self._storage = storage
        self._lock = RLock()
        self._records: dict[str, KeyRecord] = {}
        self._forensic_logger: ForensicLogger = forensic_logger or ForensicLogger()

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
                if existing.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED, KeyStatus.POISONED}:
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
            return record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED, KeyStatus.POISONED}

    def _terminalize_under_lock(self, key_id: str, *, status: KeyStatus, reason: str, event_type: str) -> bool:
        record = self._records.get(key_id)
        if record is None:
            return False
        if record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
            return False
        if status not in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
            raise ValueError("invalid terminal status")
        # Strict state machine: only ACTIVE (or POISONED, for the 24h expiry) can transition to terminal.
        if record.status not in {KeyStatus.ACTIVE, KeyStatus.POISONED}:
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

    def poison_key(self, key_id: str) -> bool:
        """Replace the authority share with random bytes and open a 24-hour forensic window.

        Called when the canary tripwire is triggered.  The poisoned share looks
        structurally valid, so the attacker's key reconstruction silently produces
        garbage instead of the real key.  All subsequent /request_share calls during
        the forensic window are logged by the ForensicLogger.

        Returns True if the key was newly poisoned, False if already terminal or unknown.
        """
        if not key_id:
            return False

        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                logger.warning("poison_key: unknown key_id=%s", key_id)
                return False
            if record.status != KeyStatus.ACTIVE:
                logger.warning(
                    "poison_key: key_id=%s already in status=%s, skipping",
                    key_id,
                    record.status.value,
                )
                return False

            # Replace the real share bytes with cryptographically random noise.
            # The POISONED share is the same length as the real share so
            # structural validation in the Shamir layer still passes.
            if record.share is not None:
                share_len = len(record.share)
                best_effort_wipe(record.share)
                record.share = bytearray(os.urandom(share_len))
            else:
                record.share = bytearray(os.urandom(33))  # fallback: default Shamir share length

            record.status = KeyStatus.POISONED
            record.terminal_at = _utcnow()
            record.terminal_reason = "canary_triggered"
            record.terminal_event_type = "key_poisoned"

        self._storage.upsert_key_metadata(
            key_id,
            {
                "status": KeyStatus.POISONED.value,
                "terminal_at": record.terminal_at.isoformat() if record.terminal_at else None,
                "terminal_reason": "canary_triggered",
            },
        )
        self._storage.append_audit_event(
            event_type="key_poisoned",
            key_id=key_id,
            client_id=record.registered_client_id,
            details={"reason": "canary_triggered"},
        )

        logger.warning(
            "Key POISONED — canary tripwire triggered for key_id=%s. "
            "24-hour forensic window opened.",
            key_id,
        )

        # Schedule automatic wipe and transition to DESTROYED after 24 hours.
        # LIMITATION: This timer is lost if the authority service restarts during
        # the 24-hour forensic window. In production, use a persistent job scheduler.
        # The poisoned share will remain in memory indefinitely if the service restarts.
        timer = threading.Timer(
            24 * 3600,
            self._expire_poisoned_key,
            kwargs={"key_id": key_id},
        )
        timer.daemon = True
        timer.name = f"forensic-expiry-{key_id[:8]}"
        timer.start()

        return True

    def _expire_poisoned_key(self, *, key_id: str) -> None:
        """Called after the 24-hour forensic window to wipe the poisoned share."""
        logger.info(
            "Forensic window closed for key_id=%s — wiping poisoned share and marking DESTROYED.",
            key_id,
        )
        with self._lock:
            self._terminalize_under_lock(
                key_id,
                status=KeyStatus.DESTROYED,
                reason="forensic_window_expired",
                event_type="key_destroyed",
            )

    def _enforce_expiry_under_lock(self, record: KeyRecord) -> None:
        if record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED, KeyStatus.POISONED}:
            return
        if _utcnow() >= record.expires_at:
            self._terminalize_under_lock(record.key_id, status=KeyStatus.EXPIRED, reason="expired", event_type="key_expired")

    def request_share(
        self,
        *,
        key_id: str,
        client_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Tuple[bool, Optional[bytes], str]:
        """Return (allowed, share_bytes, denial_reason).

        Authorization is intentionally NOT enforced here; callers must ensure the
        requesting client is allowed (e.g., per-file ACLs).

        Fix 4: When the key is POISONED, all tripwire/expiry checks are bypassed.
        The access is silently recorded via ForensicLogger, and the poisoned share
        bytes are returned with allowed=True so the attacker sees no difference
        from a normal share response.
        """
        if not key_id:
            return False, None, "missing_key_id"

        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                return False, None, "unknown_key_id"

            # --- POISONED path: bypass all tripwire checks, log forensically, return share ---
            if record.status == KeyStatus.POISONED:
                share_bytes = bytes(record.share) if record.share is not None else b""
                # Record forensic entry (outside the lock to avoid re-entrancy).
                forensic_key_id = key_id
                forensic_client_id = client_id
                forensic_ip = ip_address
                forensic_nonce = nonce

            # --- Normal path ---
            else:
                self._enforce_expiry_under_lock(record)
                if record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
                    return False, None, "revoked"

                if record.share is None:
                    # Invariant: ACTIVE keys must hold a share.
                    return False, None, "revoked"

                share_bytes = bytes(record.share)
                forensic_key_id = None  # not poisoned, no forensic recording needed
                forensic_client_id = None
                forensic_ip = None
                forensic_nonce = None

        # Forensic recording is done outside the lock.
        if forensic_key_id is not None:
            self._forensic_logger.record(
                key_id=forensic_key_id,
                client_id=forensic_client_id,
                ip_address=forensic_ip,
                nonce=forensic_nonce,
            )
            # Return poisoned share — attacker sees a normal response.
            return True, share_bytes, "ok"

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
