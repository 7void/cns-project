from __future__ import annotations

import base64
import json
import secrets
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

from crypto import aes, kdf, shamir
from crypto.utils import best_effort_wipe, random_bytes


class AuthorityRefusal(Exception):
	"""Raised when the authority refuses to return its share."""


class AuthorityTransportError(Exception):
	"""Raised when the authority cannot be reached or returns invalid responses."""


def _b64encode(data: bytes) -> str:
	return base64.b64encode(data).decode("ascii")


def _b64decode(data_b64: str) -> bytes:
	return base64.b64decode(data_b64, validate=True)


def generate_nonce() -> str:
	"""Generate a unique nonce suitable for replay protection."""
	return secrets.token_urlsafe(32)


def _context_for_kdf(*, client_id: str, nonce: bytes) -> bytes:
	return client_id.encode("utf-8") + b"|" + bytes(nonce)


@dataclass
class ClientConfig:
	authority_base_url: str
	timeout_seconds: float = 5.0


def _post_json(*, url: str, payload: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
	data = json.dumps(payload).encode("utf-8")
	req = urllib.request.Request(
		url=url,
		data=data,
		headers={"Content-Type": "application/json"},
		method="POST",
	)
	try:
		with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
			body = resp.read()
			try:
				decoded = json.loads(body.decode("utf-8"))
			except Exception as exc:  # noqa: BLE001
				raise AuthorityTransportError("authority returned non-JSON response") from exc
			if not isinstance(decoded, dict):
				raise AuthorityTransportError("authority returned unexpected JSON")
			return decoded
	except urllib.error.HTTPError as exc:
		# Try to surface server-provided detail, but avoid assuming schema.
		try:
			msg = exc.read().decode("utf-8", errors="replace")
		except Exception:
			msg = ""
		raise AuthorityTransportError(f"authority HTTP error: {exc.code} {msg}".strip()) from exc
	except urllib.error.URLError as exc:
		raise AuthorityTransportError(f"authority unreachable: {exc.reason}") from exc


class TrustedClient:
	"""Simulated trusted client holding one Shamir share.

	The client:
	- Registers the authority's share
	- Requests the authority share when needed
	- Reconstructs the AES key in memory only
	- Wipes the reconstructed key immediately after use
	"""

	def __init__(self, *, config: ClientConfig, client_id: Optional[str] = None) -> None:
		self._config = config
		self.client_id = client_id or str(uuid.uuid4())
		self._client_share: Optional[bytes] = None

	def provision_key_material(self, *, key_id: str, expires_in_seconds: int) -> None:
		"""Generate an AES key, split it (t=2,n=3), retain one share, register one with authority."""
		master_key = aes.generate_key()
		master_key_buf = bytearray(master_key)
		try:
			shares = shamir.split(master_key, t=2, n=3)
			# Retain exactly one share locally; store exactly one with authority.
			client_share = shares[0]
			authority_share = shares[1]
			unused_share = shares[2]

			# Best-effort wipe of the third share buffer if made mutable.
			best_effort_wipe(bytearray(unused_share))

			self._client_share = client_share
			self.register_key(key_id=key_id, authority_share=authority_share, expires_in_seconds=expires_in_seconds)
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
		"""Encrypt plaintext after reconstructing keys in memory; wipes keys immediately."""
		if self._client_share is None:
			raise RuntimeError("client is not provisioned with a key share")

		authority_share = self.request_authority_share(key_id=key_id)
		master_key = shamir.combine([self._client_share, authority_share])
		master_key_buf = bytearray(master_key)
		derived_key_buf: Optional[bytearray] = None
		try:
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
			best_effort_wipe(master_key_buf)
			best_effort_wipe(derived_key_buf)

	def decrypt_from_storage(self, *, envelope: dict[str, Any]) -> bytes:
		"""Decrypt an envelope produced by `encrypt_for_storage` using in-memory reconstruction."""
		if self._client_share is None:
			raise RuntimeError("client is not provisioned with a key share")
		key_id = str(envelope.get("key_id") or "")
		if not key_id:
			raise ValueError("missing key_id")
		kdf_nonce_b64 = envelope.get("kdf_nonce_b64")
		aes_payload = envelope.get("aes")
		if not isinstance(kdf_nonce_b64, str) or not isinstance(aes_payload, dict):
			raise ValueError("malformed envelope")
		kdf_nonce = _b64decode(kdf_nonce_b64)

		authority_share = self.request_authority_share(key_id=key_id)
		master_key = shamir.combine([self._client_share, authority_share])
		master_key_buf = bytearray(master_key)
		derived_key_buf: Optional[bytearray] = None
		try:
			derived_key = kdf.derive(master_key, context=_context_for_kdf(client_id=self.client_id, nonce=kdf_nonce))
			derived_key_buf = bytearray(derived_key)
			return aes.decrypt(aes_payload, key=derived_key)
		finally:
			best_effort_wipe(master_key_buf)
			best_effort_wipe(derived_key_buf)


def _demo() -> None:
	"""Minimal manual demo.

	Start the authority first:
	  uvicorn authority.main:app --reload
	"""
	client = TrustedClient(config=ClientConfig(authority_base_url="http://127.0.0.1:8000"))
	key_id = "example-key"
	client.provision_key_material(key_id=key_id, expires_in_seconds=300)

	try:
		env = client.encrypt_for_storage(key_id=key_id, plaintext=b"secret data")
		pt = client.decrypt_from_storage(envelope=env)
		print(pt.decode("utf-8"))
	except AuthorityRefusal as exc:
		print(f"Access refused: {exc}")


if __name__ == "__main__":
	_demo()

