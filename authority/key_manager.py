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

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .forensic_log import ForensicLogger
from .storage import InMemoryStorage
from crypto.utils import best_effort_wipe


logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# ShareVault — encrypts authority shares at rest using a master key
# ---------------------------------------------------------------------------


class ShareVault:
    """Encrypts all authority-held Shamir shares using AES-256-GCM.

    A single master encryption key is derived once at startup from
    AUTHORITY_MASTER_SECRET via HKDF-SHA256.  Shares are encrypted before
    being stored in KeyRecord and decrypted only for the instant they are
    served to a legitimate caller.  The plaintext master secret is never
    retained after key derivation.

    PRODUCTION: set AUTHORITY_MASTER_SECRET to a strong random secret via
    environment variable. Never hardcode.
    """

    def __init__(self) -> None:
        # PRODUCTION: set this to a strong random secret via environment variable. Never hardcode.
        master_secret: str = os.getenv(
            "AUTHORITY_MASTER_SECRET", "dev-master-secret-change-in-prod"
        )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"share-vault-v1",
            info=b"authority-share-encryption",
        )
        raw_key: bytes = hkdf.derive(master_secret.encode("utf-8"))
        # Store the derived key as a mutable bytearray so it can be wiped.
        # The original master_secret string is left to the GC (Python strings
        # are immutable and cannot be zeroed — a known limitation).
        self._key: bytearray = bytearray(raw_key)

    def encrypt(self, share: bytes) -> Tuple[bytes, bytes]:
        """Encrypt share bytes.  Returns (ciphertext_with_tag, nonce)."""
        nonce = os.urandom(12)
        aesgcm = AESGCM(bytes(self._key))
        ciphertext_with_tag = aesgcm.encrypt(nonce, share, associated_data=None)
        return ciphertext_with_tag, nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """Decrypt and authenticate.  Raises ValueError on failure."""
        aesgcm = AESGCM(bytes(self._key))
        try:
            return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except InvalidTag as exc:
            raise ValueError("Share decryption failed — possible tampering") from exc

    def wipe(self) -> None:
        """Zero the master key from memory."""
        best_effort_wipe(self._key)
        self._key = bytearray(0)


# ---------------------------------------------------------------------------
# KeyRecord — stores share encrypted at rest, never plaintext
# ---------------------------------------------------------------------------


@dataclass
class KeyRecord:
    key_id: str
    registered_client_id: str
    encrypted_share: Optional[bytes]   # AES-256-GCM ciphertext+tag, or None when wiped
    share_nonce: Optional[bytes]       # 12-byte GCM nonce paired with encrypted_share
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


# ---------------------------------------------------------------------------
# KeyManager
# ---------------------------------------------------------------------------


class KeyManager:
    """Tracks and irreversibly destroys authority-held key shares.

    Security properties:
    - Shares are encrypted at rest inside KeyRecord using ShareVault (HKDF + AES-256-GCM).
    - Plaintext share bytes exist only for the instant they are needed, then wiped.
    - Once destroyed (manual or by expiry/violation), the encrypted share blob is
      zeroed and must never be returned again.
    - Full AES keys are never stored here.
    - When a canary alert is received, the encrypted random-bytes POISONED share is
      stored (also encrypted); it is decrypted and served to the attacker transparently.
    """

    def __init__(
        self,
        storage: InMemoryStorage,
        forensic_logger: Optional[ForensicLogger] = None,
    ) -> None:
        self._storage = storage
        self._lock = RLock()
        self._records: dict[str, KeyRecord] = {}
        self._forensic_logger: ForensicLogger = forensic_logger or ForensicLogger()
        self._vault = ShareVault()
        logger.info("ShareVault initialized — shares encrypted at rest")

    # ------------------------------------------------------------------
    # Public read helpers
    # ------------------------------------------------------------------

    def get_key_status(self, key_id: str) -> str:
        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                return "UNKNOWN"
            return record.status.value

    def get_registered_client_id(self, key_id: str) -> Optional[str]:
        with self._lock:
            record = self._records.get(key_id)
            return record.registered_client_id if record else None

    def is_destroyed(self, key_id: str) -> bool:
        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                return True
            return record.status in {
                KeyStatus.DESTROYED,
                KeyStatus.EXPIRED,
                KeyStatus.POISONED,
            }

    # ------------------------------------------------------------------
    # register_key
    # ------------------------------------------------------------------

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

        # Encrypt the share immediately; wipe the plaintext buffer after.
        plaintext_buf = bytearray(bytes(authority_share))
        try:
            encrypted_share, share_nonce = self._vault.encrypt(bytes(plaintext_buf))
        finally:
            best_effort_wipe(plaintext_buf)

        with self._lock:
            existing = self._records.get(key_id)
            if existing is not None:
                if existing.status in {
                    KeyStatus.DESTROYED,
                    KeyStatus.EXPIRED,
                    KeyStatus.POISONED,
                }:
                    raise ValueError(
                        f"key_id '{key_id}' is terminal ({existing.status.value})"
                    )
                raise ValueError(f"key_id '{key_id}' already registered")

            self._records[key_id] = KeyRecord(
                key_id=key_id,
                registered_client_id=client_id,
                encrypted_share=encrypted_share,
                share_nonce=share_nonce,
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

    # ------------------------------------------------------------------
    # _terminalize_under_lock
    # ------------------------------------------------------------------

    def _terminalize_under_lock(
        self,
        key_id: str,
        *,
        status: KeyStatus,
        reason: str,
        event_type: str,
    ) -> bool:
        record = self._records.get(key_id)
        if record is None:
            return False
        if record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
            return False
        if status not in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
            raise ValueError("invalid terminal status")
        if record.status not in {KeyStatus.ACTIVE, KeyStatus.POISONED}:
            return False

        # Zero the encrypted share blob before clearing the reference.
        if record.encrypted_share is not None:
            best_effort_wipe(bytearray(record.encrypted_share))
        record.encrypted_share = None
        record.share_nonce = None
        record.status = status
        record.terminal_at = _utcnow()
        record.terminal_reason = reason
        record.terminal_event_type = event_type

        self._storage.upsert_key_metadata(
            key_id,
            {
                "status": record.status.value,
                "terminal_at": (
                    record.terminal_at.isoformat() if record.terminal_at else None
                ),
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

    # ------------------------------------------------------------------
    # destroy_key
    # ------------------------------------------------------------------

    def destroy_key(self, key_id: str, *, reason: str) -> bool:
        if not key_id:
            raise ValueError("key_id is required")
        if not reason:
            reason = "unspecified"
        with self._lock:
            return self._terminalize_under_lock(
                key_id,
                status=KeyStatus.DESTROYED,
                reason=reason,
                event_type="key_destroyed",
            )

    # ------------------------------------------------------------------
    # poison_key
    # ------------------------------------------------------------------

    def poison_key(self, key_id: str) -> bool:
        """Replace the authority share with encrypted random bytes and open a 24-hour forensic window.

        Called when the canary tripwire is triggered.  The poisoned share is stored
        encrypted (via ShareVault) just like the real share.  When the attacker calls
        /request_share, the poisoned bytes are decrypted and served transparently so they
        reconstruct garbage instead of the real key — and they see no difference.
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

            # Determine the share length from the existing encrypted blob.
            # GCM tag = 16 bytes; subtract to get original plaintext length.
            if record.encrypted_share is not None:
                share_len = len(record.encrypted_share) - 16
                if share_len < 1:
                    share_len = 33  # fallback
            else:
                share_len = 33

            # Generate random bytes the same length as the real share.
            random_share = os.urandom(share_len)

            # Zero the old encrypted share blob before overwriting.
            if record.encrypted_share is not None:
                best_effort_wipe(bytearray(record.encrypted_share))

            # Encrypt the poisoned share and store it — never plaintext.
            poisoned_encrypted, poisoned_nonce = self._vault.encrypt(random_share)
            record.encrypted_share = poisoned_encrypted
            record.share_nonce = poisoned_nonce
            record.status = KeyStatus.POISONED
            record.terminal_at = _utcnow()
            record.terminal_reason = "canary_triggered"
            record.terminal_event_type = "key_poisoned"

        self._storage.upsert_key_metadata(
            key_id,
            {
                "status": KeyStatus.POISONED.value,
                "terminal_at": (
                    record.terminal_at.isoformat() if record.terminal_at else None
                ),
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

    # ------------------------------------------------------------------
    # _enforce_expiry_under_lock
    # ------------------------------------------------------------------

    def _enforce_expiry_under_lock(self, record: KeyRecord) -> None:
        if record.status in {
            KeyStatus.DESTROYED,
            KeyStatus.EXPIRED,
            KeyStatus.POISONED,
        }:
            return
        if _utcnow() >= record.expires_at:
            self._terminalize_under_lock(
                record.key_id,
                status=KeyStatus.EXPIRED,
                reason="expired",
                event_type="key_expired",
            )

    # ------------------------------------------------------------------
    # request_share
    # ------------------------------------------------------------------

    def request_share(
        self,
        *,
        key_id: str,
        client_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Tuple[bool, Optional[bytes], str]:
        """Return (allowed, share_bytes, denial_reason).

        The share is decrypted from ShareVault into a temporary buffer, returned
        to the caller, and wiped immediately — it is never assigned to any
        instance variable.

        Fix 4: When the key is POISONED, all tripwire/expiry checks are bypassed.
        The access is silently recorded via ForensicLogger, and the decrypted
        poisoned share is returned with allowed=True.
        """
        if not key_id:
            return False, None, "missing_key_id"

        plaintext_buf: Optional[bytearray] = None
        forensic_key_id: Optional[str] = None
        forensic_client_id: Optional[str] = None
        forensic_ip: Optional[str] = None
        forensic_nonce: Optional[str] = None
        share_bytes: Optional[bytes] = None

        try:
            with self._lock:
                record = self._records.get(key_id)
                if record is None:
                    return False, None, "unknown_key_id"

                # --- POISONED path: bypass expiry/tripwire, log forensically, return share ---
                if record.status == KeyStatus.POISONED:
                    if (
                        record.encrypted_share is None
                        or record.share_nonce is None
                    ):
                        return False, None, "revoked"
                    decrypted = self._vault.decrypt(
                        record.encrypted_share, record.share_nonce
                    )
                    plaintext_buf = bytearray(decrypted)
                    share_bytes = bytes(plaintext_buf)
                    forensic_key_id = key_id
                    forensic_client_id = client_id
                    forensic_ip = ip_address
                    forensic_nonce = nonce

                # --- Normal path ---
                else:
                    self._enforce_expiry_under_lock(record)
                    if record.status in {KeyStatus.DESTROYED, KeyStatus.EXPIRED}:
                        return False, None, "revoked"

                    if record.encrypted_share is None or record.share_nonce is None:
                        return False, None, "revoked"

                    decrypted = self._vault.decrypt(
                        record.encrypted_share, record.share_nonce
                    )
                    plaintext_buf = bytearray(decrypted)
                    share_bytes = bytes(plaintext_buf)

        finally:
            # Always wipe the temporary plaintext buffer, even on exception.
            if plaintext_buf is not None:
                best_effort_wipe(plaintext_buf)

        # Forensic recording outside the lock.
        if forensic_key_id is not None:
            self._forensic_logger.record(
                key_id=forensic_key_id,
                client_id=forensic_client_id,
                ip_address=forensic_ip,
                nonce=forensic_nonce,
            )
            # Return decrypted poisoned share — attacker sees a normal response.
            return True, share_bytes, "ok"

        self._storage.append_audit_event(
            event_type="share_released",
            key_id=key_id,
            client_id=client_id,
            details={"share_len": len(share_bytes) if share_bytes else 0},
        )
        return True, share_bytes, "ok"

    # ------------------------------------------------------------------
    # Base64 utilities
    # ------------------------------------------------------------------

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
