from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import secrets
import ssl
import threading
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

# Allow running as a script (e.g., `python client/client.py`) by ensuring the
# project root is on sys.path so top-level modules like `crypto` can be imported.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
	sys.path.insert(0, PROJECT_ROOT)

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto import aes, kdf, shamir
from crypto.utils import best_effort_wipe, random_bytes

from storage.minio_adapter import StorageError, download_object, upload_object


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuthorityRefusal(Exception):
	"""Raised when the authority refuses to return its share."""


class AuthorityTransportError(Exception):
	"""Raised when the authority cannot be reached or returns invalid responses."""


# ---------------------------------------------------------------------------
# Encrypted share container
# ---------------------------------------------------------------------------


@dataclass
class EncryptedShare:
	"""AES-256-GCM encrypted Shamir share, protected by a PBKDF2-derived key.

	The plaintext share bytes are never held in memory beyond the instant they
	are encrypted (on store) or decrypted (on use).
	"""

	ciphertext: bytes  # AES-256-GCM ciphertext (share bytes encrypted)
	salt: bytes        # 16-byte random PBKDF2 salt
	nonce: bytes       # 12-byte AES-GCM nonce
	tag: bytes         # 16-byte AES-GCM authentication tag


# PBKDF2 parameters — high iteration count to slow brute-force attempts.
_PBKDF2_HASH = "sha256"
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_DK_LEN = 32  # 256-bit AES key


def _derive_share_key(password: str, salt: bytes) -> bytearray:
	"""Derive a 32-byte AES key from password + salt using PBKDF2-HMAC-SHA256."""
	raw = hashlib.pbkdf2_hmac(
		_PBKDF2_HASH,
		password.encode("utf-8"),
		salt,
		iterations=_PBKDF2_ITERATIONS,
		dklen=_PBKDF2_DK_LEN,
	)
	return bytearray(raw)


def _encrypt_share(share: bytes, password: str) -> EncryptedShare:
	"""Encrypt a Shamir share using AES-256-GCM with a PBKDF2-derived key.

	The derived key is wiped immediately after use. The plaintext share should
	be wiped by the caller.
	"""
	salt = os.urandom(16)
	nonce = os.urandom(12)

	derived_key_buf = _derive_share_key(password, salt)
	try:
		aesgcm = AESGCM(bytes(derived_key_buf))
		# AESGCM.encrypt() returns ciphertext + 16-byte tag appended.
		ct_with_tag = aesgcm.encrypt(nonce, share, associated_data=None)
	finally:
		best_effort_wipe(derived_key_buf)

	# Split off the 16-byte GCM authentication tag from the end.
	ciphertext = ct_with_tag[:-16]
	tag = ct_with_tag[-16:]

	return EncryptedShare(ciphertext=ciphertext, salt=salt, nonce=nonce, tag=tag)


def _decrypt_share(encrypted: EncryptedShare, password: str) -> bytes:
	"""Decrypt an EncryptedShare and return the plaintext share bytes.

	The derived key is wiped immediately after use.

	Raises:
	    ValueError: if the password is wrong or the ciphertext was tampered with.
	"""
	derived_key_buf = _derive_share_key(password, encrypted.salt)
	try:
		aesgcm = AESGCM(bytes(derived_key_buf))
		ct_with_tag = encrypted.ciphertext + encrypted.tag
		try:
			plaintext = aesgcm.decrypt(encrypted.nonce, ct_with_tag, associated_data=None)
		except InvalidTag as exc:
			raise ValueError("wrong password or corrupted share") from exc
	finally:
		best_effort_wipe(derived_key_buf)

	return plaintext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64encode(data: bytes) -> str:
	return base64.b64encode(data).decode("ascii")


def _b64decode(data_b64: str) -> bytes:
	return base64.b64decode(data_b64, validate=True)


def generate_nonce() -> str:
	"""Generate a unique nonce suitable for replay protection."""
	return secrets.token_urlsafe(32)


def _context_for_kdf(*, client_id: str, nonce: bytes) -> bytes:
	return client_id.encode("utf-8") + b"|" + bytes(nonce)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class ClientConfig:
	authority_base_url: str
	canary_base_url: str = ""
	timeout_seconds: float = 5.0

	# If canary_base_url is empty, fall back to CANARY_BASE_URL env var or default.
	def __post_init__(self) -> None:
		if not self.canary_base_url:
			self.canary_base_url = os.getenv("CANARY_BASE_URL", "http://127.0.0.1:8002")


# ---------------------------------------------------------------------------
# SSL context (accepts self-signed certificates for local dev)
# ---------------------------------------------------------------------------

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _try_register_canary(
	*,
	canary_base_url: str,
	key_id: str,
	client_id: str,
	canary_share: bytes,
	timeout_seconds: float,
) -> bool:
	"""POST Share 3 to the canary service as a honeypot tripwire.

	Returns True if the canary service accepted the share, False on any error.
	This function never raises — failure is a silent fallback to the old wipe behaviour.
	"""
	try:
		url = f"{canary_base_url.rstrip('/')}/register_canary"
		payload: dict[str, Any] = {
			"key_id": key_id,
			"client_id": client_id,
			"canary_share_b64": _b64encode(canary_share),
		}
		body = _post_json(url=url, payload=payload, timeout_seconds=timeout_seconds)
		if body.get("status") == "ok":
			return True
		return False
	except Exception:  # noqa: BLE001
		# Canary service unavailable — silently fall back to discarding Share 3.
		return False


def _post_json(*, url: str, payload: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
	data = json.dumps(payload).encode("utf-8")
	req = urllib.request.Request(
		url=url,
		data=data,
		headers={"Content-Type": "application/json"},
		method="POST",
	)
	try:
		with urllib.request.urlopen(req, timeout=timeout_seconds, context=_SSL_CTX) as resp:
			body = resp.read()
			try:
				decoded = json.loads(body.decode("utf-8"))
			except Exception as exc:  # noqa: BLE001
				raise AuthorityTransportError("authority returned non-JSON response") from exc
			if not isinstance(decoded, dict):
				raise AuthorityTransportError("authority returned unexpected JSON")
			return decoded
	except urllib.error.HTTPError as exc:
		try:
			msg = exc.read().decode("utf-8", errors="replace")
		except Exception:
			msg = ""
		raise AuthorityTransportError(f"authority HTTP error: {exc.code} {msg}".strip()) from exc
	except urllib.error.URLError as exc:
		raise AuthorityTransportError(f"authority unreachable: {exc.reason}") from exc


# ---------------------------------------------------------------------------
# TrustedClient
# ---------------------------------------------------------------------------


class TrustedClient:
	"""Simulated trusted client holding one Shamir share.

	The client:
	- Registers the authority's share
	- Requests the authority share when needed
	- Reconstructs the AES key in memory only
	- Wipes the reconstructed key immediately after use

	Share 1 is NEVER stored as plaintext. It is encrypted at rest in memory
	using AES-256-GCM with a PBKDF2-derived key and stored as an EncryptedShare.
	"""

	def __init__(self, *, config: ClientConfig, client_id: Optional[str] = None) -> None:
		self._config = config
		self.client_id = client_id or str(uuid.uuid4())
		# Share 1 stored encrypted-at-rest; never held as plaintext bytes.
		self._encrypted_share: Optional[EncryptedShare] = None
		# SECURITY TRADEOFF: The password must be retained in memory so that
		# encrypt_for_storage() and decrypt_from_storage() can re-derive the
		# share-encryption key on each call without requiring the caller to pass
		# the password each time. In a production system, consider requesting the
		# password fresh from the user on every cryptographic operation instead.
		# Python strings are immutable and cannot be zeroed; this is a known
		# limitation of the Python memory model.
		self._password: Optional[str] = None

	def set_password(self, password: str) -> None:
		"""Store the password used to encrypt and decrypt the client share in memory."""
		if not password:
			raise ValueError("password must be non-empty")
		self._password = password

	def set_client_share(self, *, client_share: bytes, password: str) -> None:
		"""Accept an externally provided share (e.g. imported from collaborator) and encrypt it.

		The plaintext share is wiped immediately after encryption.
		"""
		if not isinstance(client_share, (bytes, bytearray)) or len(client_share) == 0:
			raise ValueError("client_share must be non-empty bytes")
		if not password:
			raise ValueError("password must be non-empty")
		share_buf = bytearray(client_share)
		try:
			self._encrypted_share = _encrypt_share(bytes(share_buf), password)
			self._password = password
		finally:
			best_effort_wipe(share_buf)

	def _require_share(self) -> None:
		"""Raise RuntimeError if the client is not provisioned with an encrypted share."""
		if self._encrypted_share is None:
			raise RuntimeError("client is not provisioned with a key share")
		if self._password is None:
			raise RuntimeError("client password not set; call set_password() first")

	def _get_plaintext_share(self) -> bytes:
		"""Decrypt and return the plaintext Share 1. Caller MUST wipe the result."""
		self._require_share()
		return _decrypt_share(self._encrypted_share, self._password)  # type: ignore[arg-type]

	def provision_key_material(self, *, key_id: str, expires_in_seconds: int) -> None:
		"""Generate an AES key, split it (t=2,n=3), retain one share, register one with authority.

		Share 1 (client_share)    — encrypted-at-rest using self._password, stored as EncryptedShare.
		Share 2 (authority_share) — registered with the authority service.
		Share 3 (canary_share)    — sent to the canary service as a honeypot tripwire.
		                            If the canary service is unreachable, Share 3 is
		                            zeroed immediately (original fallback behaviour).
		"""
		if self._password is None:
			raise RuntimeError(
				"call set_password() before provision_key_material() so Share 1 can be encrypted"
			)
		master_key = aes.generate_key()
		master_key_buf = bytearray(master_key)
		try:
			shares = shamir.split(master_key, t=2, n=3)
			client_share_buf = bytearray(shares[0])
			authority_share = shares[1]
			canary_share = shares[2]

			try:
				# Encrypt Share 1 immediately; plaintext share is wiped in finally.
				self._encrypted_share = _encrypt_share(bytes(client_share_buf), self._password)
			finally:
				best_effort_wipe(client_share_buf)

			# Attempt to register Share 3 with the canary tripwire service.
			# On failure (service unreachable), fall back to zeroing the share.
			canary_registered = _try_register_canary(
				canary_base_url=self._config.canary_base_url,
				key_id=key_id,
				client_id=self.client_id,
				canary_share=canary_share,
				timeout_seconds=self._config.timeout_seconds,
			)
			if not canary_registered:
				best_effort_wipe(bytearray(canary_share))  # fallback: old behavior

			self.register_key(
				key_id=key_id,
				authority_share=authority_share,
				expires_in_seconds=expires_in_seconds,
			)
		finally:
			best_effort_wipe(master_key_buf)

	def register_key(
		self,
		*,
		key_id: str,
		authority_share: bytes,
		expires_in_seconds: int,
	) -> None:
		payload = {
			"key_id": key_id,
			"client_id": self.client_id,
			"authority_share_b64": _b64encode(authority_share),
			"expires_in_seconds": int(expires_in_seconds),
			"nonce": generate_nonce(),
		}
		url = f"{self._config.authority_base_url.rstrip('/')}/register_key"
		body = _post_json(url=url, payload=payload, timeout_seconds=self._config.timeout_seconds)
		if body.get("status") != "ok":
			raise AuthorityTransportError(f"register_key failed: {body}")

	def request_authority_share(self, *, key_id: str) -> bytes:
		payload = {
			"key_id": key_id,
			"client_id": self.client_id,
			"nonce": generate_nonce(),
		}
		url = f"{self._config.authority_base_url.rstrip('/')}/request_share"
		body = _post_json(url=url, payload=payload, timeout_seconds=self._config.timeout_seconds)
		if body.get("status") != "ok":
			raise AuthorityRefusal(body.get("denial_reason") or "denied")
		share_b64 = body.get("authority_share_b64")
		if not share_b64:
			raise AuthorityRefusal("missing_share")
		return _b64decode(share_b64)

	def destroy_key(self, *, key_id: str, reason: str = "client_requested") -> bool:
		payload = {
			"key_id": key_id,
			"client_id": self.client_id,
			"nonce": generate_nonce(),
			"reason": reason,
		}
		url = f"{self._config.authority_base_url.rstrip('/')}/destroy_key"
		body = _post_json(url=url, payload=payload, timeout_seconds=self._config.timeout_seconds)
		return bool(body.get("destroyed"))

	def encrypt_for_storage(
		self,
		*,
		key_id: str,
		plaintext: bytes,
	) -> dict[str, Any]:
		"""Encrypt plaintext after reconstructing keys in memory; wipes all key material immediately."""
		self._require_share()

		# Decrypt Share 1 from encrypted-at-rest storage into a temporary buffer.
		client_share_buf = bytearray(self._get_plaintext_share())
		authority_share = self.request_authority_share(key_id=key_id)
		master_key_buf: Optional[bytearray] = None
		derived_key_buf: Optional[bytearray] = None
		try:
			master_key = shamir.combine([bytes(client_share_buf), authority_share])
			master_key_buf = bytearray(master_key)
			kdf_nonce = random_bytes(16)
			derived_key = kdf.derive(master_key, context=_context_for_kdf(client_id=self.client_id, nonce=kdf_nonce))
			derived_key_buf = bytearray(derived_key)
			aes_payload = aes.encrypt(plaintext, key=derived_key)
			return {
				"key_id": key_id,
				"client_id": self.client_id,
				"kdf_nonce_b64": _b64encode(kdf_nonce),
				"aes": aes_payload,
			}
		finally:
			best_effort_wipe(client_share_buf)
			best_effort_wipe(master_key_buf)
			best_effort_wipe(derived_key_buf)

	def decrypt_from_storage(self, *, envelope: dict[str, Any]) -> bytes:
		"""Decrypt an envelope produced by `encrypt_for_storage` using in-memory reconstruction."""
		self._require_share()
		key_id = str(envelope.get("key_id") or "")
		if not key_id:
			raise ValueError("missing key_id")
		kdf_nonce_b64 = envelope.get("kdf_nonce_b64")
		aes_payload = envelope.get("aes")
		if not isinstance(kdf_nonce_b64, str) or not isinstance(aes_payload, dict):
			raise ValueError("malformed envelope")
		kdf_nonce = _b64decode(kdf_nonce_b64)

		# Decrypt Share 1 from encrypted-at-rest storage into a temporary buffer.
		client_share_buf = bytearray(self._get_plaintext_share())
		authority_share = self.request_authority_share(key_id=key_id)
		master_key_buf: Optional[bytearray] = None
		derived_key_buf: Optional[bytearray] = None
		try:
			master_key = shamir.combine([bytes(client_share_buf), authority_share])
			master_key_buf = bytearray(master_key)
			derived_key = kdf.derive(master_key, context=_context_for_kdf(client_id=self.client_id, nonce=kdf_nonce))
			derived_key_buf = bytearray(derived_key)
			return aes.decrypt(aes_payload, key=derived_key)
		finally:
			best_effort_wipe(client_share_buf)
			best_effort_wipe(master_key_buf)
			best_effort_wipe(derived_key_buf)


# ---------------------------------------------------------------------------
# Health check / wait helpers
# ---------------------------------------------------------------------------


def _get_json(*, url: str, timeout_seconds: float) -> dict[str, Any]:
	req = urllib.request.Request(url=url, method="GET")
	try:
		with urllib.request.urlopen(req, timeout=timeout_seconds, context=_SSL_CTX) as resp:
			body = resp.read()
			decoded = json.loads(body.decode("utf-8"))
			if not isinstance(decoded, dict):
				raise AuthorityTransportError("authority returned unexpected JSON")
			return decoded
	except urllib.error.URLError as exc:
		raise AuthorityTransportError(f"authority unreachable: {exc.reason}") from exc
	except Exception as exc:  # noqa: BLE001
		raise AuthorityTransportError("authority health check failed") from exc


def _wait_for_authority(*, config: ClientConfig, attempts: int = 30, delay_s: float = 0.2) -> None:
	url = f"{config.authority_base_url.rstrip('/')}/healthz"
	for _ in range(attempts):
		try:
			body = _get_json(url=url, timeout_seconds=min(1.0, config.timeout_seconds))
			if body.get("status") == "ok":
				return
		except AuthorityTransportError:
			import time

			time.sleep(delay_s)
	raise AuthorityTransportError(
		"authority did not become ready. Start it with: uvicorn authority.main:app --host 127.0.0.1 --port 8000"
	)


def _start_authority_in_background(*, host: str = "127.0.0.1", port: int = 8000) -> None:
	"""Best-effort helper for local demos.

	Starts the FastAPI authority using uvicorn in a daemon thread.
	"""
	try:
		import uvicorn
	except Exception:  # noqa: BLE001
		return

	config = uvicorn.Config(
		"authority.main:app",
		host=host,
		port=port,
		log_level="error",
		access_log=False,
	)
	server = uvicorn.Server(config)

	def _run() -> None:
		server.run()

	threading.Thread(target=_run, name="authority-server", daemon=True).start()


# ---------------------------------------------------------------------------
# Demo entry point
# ---------------------------------------------------------------------------


def _demo() -> None:
	"""End-to-end demo (client provisions, storage holds ciphertext, authority can revoke).

	Requirements:
	- Authority running (start with: `uvicorn authority.main:app --host 127.0.0.1 --port 8000`)
	- MinIO env vars set (MINIO_ACCESS_KEY/MINIO_SECRET_KEY, etc.)
	"""
	config = ClientConfig(authority_base_url=os.getenv("AUTHORITY_BASE_URL", "http://127.0.0.1:8000"))
	try:
		try:
			_wait_for_authority(config=config)
		except AuthorityTransportError:
			# Local convenience: auto-start authority if not running.
			_start_authority_in_background(host="127.0.0.1", port=8000)
			_wait_for_authority(config=config)
		key_id = f"demo-key-{uuid.uuid4()}"
		object_id = f"demo-object-{uuid.uuid4()}"

		client = TrustedClient(config=config)
		client.set_password("demo-password-change-in-production")
		client.provision_key_material(key_id=key_id, expires_in_seconds=300)

		envelope = client.encrypt_for_storage(key_id=key_id, plaintext=b"Confidential demo payload")
		try:
			upload_object(object_id, json.dumps(envelope).encode("utf-8"))
		except StorageError as exc:
			minio_endpoint = os.getenv("MINIO_ENDPOINT")
			raise StorageError(
				f"{exc}. MINIO_ENDPOINT is currently set to: {minio_endpoint!r}. "
				"For local MinIO: run `docker compose up -d` then set MINIO_ENDPOINT=localhost:9000, "
				"MINIO_ACCESS_KEY=minioadmin, MINIO_SECRET_KEY=minioadmin."
			) from exc

		blob = download_object(object_id)
		loaded = json.loads(blob.decode("utf-8"))
		if not isinstance(loaded, dict):
			raise ValueError("storage object is not a JSON dict")
		pt = client.decrypt_from_storage(envelope=loaded)
		print(pt.decode("utf-8", errors="replace"))
		print(f"OK: key_id={key_id} object_id={object_id} client_id={client.client_id}")
	except (AuthorityRefusal, AuthorityTransportError, StorageError, ValueError, json.JSONDecodeError) as exc:
		print(f"Demo failed: {exc}")


if __name__ == "__main__":
	_demo()
