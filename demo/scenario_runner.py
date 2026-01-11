from __future__ import annotations

import base64
import json
import logging
import secrets
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Optional

import uvicorn

from crypto import aes, kdf, shamir
from crypto.utils import best_effort_wipe, random_bytes
from storage.minio_adapter import StorageError, delete_object, download_object, upload_object


class AuthorityTransportError(RuntimeError):
	pass


class AuthorityRefusal(RuntimeError):
	pass


def _b64e(data: bytes) -> str:
	return base64.b64encode(data).decode("ascii")


def _b64d(data_b64: str) -> bytes:
	return base64.b64decode(data_b64, validate=True)


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
		try:
			msg = exc.read().decode("utf-8", errors="replace")
		except Exception:
			msg = ""
		raise AuthorityTransportError(f"authority HTTP error: {exc.code} {msg}".strip()) from exc
	except urllib.error.URLError as exc:
		raise AuthorityTransportError(f"authority unreachable: {exc.reason}") from exc


def _get_json(*, url: str, timeout_seconds: float) -> dict[str, Any]:
	req = urllib.request.Request(url=url, method="GET")
	try:
		with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
			body = resp.read()
			decoded = json.loads(body.decode("utf-8"))
			if not isinstance(decoded, dict):
				raise AuthorityTransportError("authority returned unexpected JSON")
			return decoded
	except Exception as exc:  # noqa: BLE001
		raise AuthorityTransportError("health check failed") from exc


def _context_for_kdf(*, client_id: str, nonce: bytes) -> bytes:
	return client_id.encode("utf-8") + b"|" + bytes(nonce)


@dataclass(frozen=True)
class DemoConfig:
	authority_base_url: str = "http://127.0.0.1:8000"
	http_timeout_seconds: float = 5.0
	expires_in_seconds: int = 60


class AuthorityServer:
	def __init__(self, host: str = "127.0.0.1", port: int = 8000) -> None:
		self._host = host
		self._port = port
		self._server: Optional[uvicorn.Server] = None
		self._thread: Optional[threading.Thread] = None

	def start(self) -> None:
		config = uvicorn.Config(
			"authority.main:app",
			host=self._host,
			port=self._port,
			log_level="error",
			access_log=False,
		)
		server = uvicorn.Server(config)
		self._server = server

		def _run() -> None:
			server.run()

		t = threading.Thread(target=_run, name="authority-server", daemon=True)
		self._thread = t
		t.start()

	def stop(self) -> None:
		if self._server is not None:
			self._server.should_exit = True
		if self._thread is not None:
			self._thread.join(timeout=5)


def _authority_register_share(
	*,
	cfg: DemoConfig,
	key_id: str,
	client_id: str,
	authority_share: bytes,
) -> None:
	url = f"{cfg.authority_base_url.rstrip('/')}/register_key"
	body = _post_json(
		url=url,
		payload={
			"key_id": key_id,
			"client_id": client_id,
			"authority_share_b64": _b64e(authority_share),
			"expires_in_seconds": cfg.expires_in_seconds,
			"nonce": secrets.token_urlsafe(32),
		},
		timeout_seconds=cfg.http_timeout_seconds,
	)
	if body.get("status") != "ok":
		raise AuthorityTransportError(f"register_key failed: {body}")


def _authority_request_share(
	*,
	cfg: DemoConfig,
	key_id: str,
	client_id: str,
	nonce: str,
) -> dict[str, Any]:
	url = f"{cfg.authority_base_url.rstrip('/')}/request_share"
	body = _post_json(
		url=url,
		payload={"key_id": key_id, "client_id": client_id, "nonce": nonce},
		timeout_seconds=cfg.http_timeout_seconds,
	)
	return body


def _authority_destroy_key(*, cfg: DemoConfig, key_id: str, client_id: str, nonce: str, reason: str) -> dict[str, Any]:
	url = f"{cfg.authority_base_url.rstrip('/')}/destroy_key"
	return _post_json(
		url=url,
		payload={"key_id": key_id, "client_id": client_id, "nonce": nonce, "reason": reason},
		timeout_seconds=cfg.http_timeout_seconds,
	)


def _wait_for_authority(cfg: DemoConfig, attempts: int = 50, delay_s: float = 0.1) -> None:
	url = f"{cfg.authority_base_url.rstrip('/')}/healthz"
	for _ in range(attempts):
		try:
			body = _get_json(url=url, timeout_seconds=1.0)
			if body.get("status") == "ok":
				return
		except AuthorityTransportError:
			time.sleep(delay_s)
	raise AuthorityTransportError("authority did not become ready")


def run_demo() -> None:
	logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
	log = logging.getLogger("scenario")

	cfg = DemoConfig()
	server = AuthorityServer()

	log.info("Starting authority service")
	server.start()
	try:
		_wait_for_authority(cfg)

		key_id = f"demo-key-{uuid.uuid4()}"
		object_id = f"demo-object-{uuid.uuid4()}"
		client_id = f"client-{uuid.uuid4()}"

		plaintext = b"Confidential: project-grade irreversible revocation demo"
		log.info("Generated plaintext (len=%d)", len(plaintext))

		master_key = aes.generate_key()
		master_key_buf = bytearray(master_key)
		log.info("Generated AES-256 master key (not logged)")

		try:
			shares = shamir.split(master_key, t=2, n=3)
			client_share = shares[0]
			authority_share = shares[1]
			unused_share = shares[2]
			best_effort_wipe(bytearray(unused_share))
			log.info("Split master key with Shamir (t=2, n=3)")

			_authority_register_share(cfg=cfg, key_id=key_id, client_id=client_id, authority_share=authority_share)
			log.info("Stored one share in authority")
			log.info("Stored one share in client (in-memory)")

		finally:
			best_effort_wipe(master_key_buf)

		# Encrypt & upload
		req_nonce_1 = secrets.token_urlsafe(32)
		resp1 = _authority_request_share(cfg=cfg, key_id=key_id, client_id=client_id, nonce=req_nonce_1)
		if resp1.get("status") != "ok":
			raise AuthorityRefusal(f"request denied unexpectedly: {resp1}")
		if resp1.get("key_status") != "ACTIVE":
			raise RuntimeError(f"expected ACTIVE key_status, got: {resp1.get('key_status')}")
		authority_share_1 = _b64d(resp1["authority_share_b64"])
		master_key_1 = shamir.combine([client_share, authority_share_1])
		master_key_1_buf = bytearray(master_key_1)
		derived_key_buf: Optional[bytearray] = None
		try:
			kdf_nonce = random_bytes(16)
			derived_key = kdf.derive(master_key_1, context=_context_for_kdf(client_id=client_id, nonce=kdf_nonce))
			derived_key_buf = bytearray(derived_key)

			enc = aes.encrypt(plaintext, key=derived_key)
			envelope = {
				"key_id": key_id,
				"client_id": client_id,
				"kdf_nonce_b64": _b64e(kdf_nonce),
				"aes": enc,
			}
			blob = json.dumps(envelope).encode("utf-8")
			upload_object(object_id, blob)
			log.info("Uploaded encrypted blob to untrusted storage (object_id=%s, bytes=%d)", object_id, len(blob))
		finally:
			best_effort_wipe(master_key_1_buf)
			best_effort_wipe(derived_key_buf)

		# Happy-path decrypt
		blob2 = download_object(object_id)
		log.info("Downloaded encrypted blob from storage (bytes=%d)", len(blob2))
		env2 = json.loads(blob2.decode("utf-8"))
		req_nonce_2 = secrets.token_urlsafe(32)
		resp2 = _authority_request_share(cfg=cfg, key_id=key_id, client_id=client_id, nonce=req_nonce_2)
		if resp2.get("status") != "ok":
			raise AuthorityRefusal(f"request denied unexpectedly: {resp2}")
		if resp2.get("key_status") != "ACTIVE":
			raise RuntimeError(f"expected ACTIVE key_status, got: {resp2.get('key_status')}")
		authority_share_2 = _b64d(resp2["authority_share_b64"])
		master_key_2 = shamir.combine([client_share, authority_share_2])
		master_key_2_buf = bytearray(master_key_2)
		derived_key_2_buf: Optional[bytearray] = None
		try:
			kdf_nonce2 = _b64d(env2["kdf_nonce_b64"])
			derived_key2 = kdf.derive(master_key_2, context=_context_for_kdf(client_id=client_id, nonce=kdf_nonce2))
			derived_key_2_buf = bytearray(derived_key2)
			pt2 = aes.decrypt(env2["aes"], key=derived_key2)
			if pt2 != plaintext:
				raise RuntimeError("decryption produced unexpected plaintext")
			log.info("Access allowed: decryption succeeded (plaintext not logged)")
		finally:
			best_effort_wipe(master_key_2_buf)
			best_effort_wipe(derived_key_2_buf)

		# Trigger revocation via attack detection: replay the same nonce
		replay_nonce = secrets.token_urlsafe(32)
		log.info("Triggering revocation via nonce replay (attack detector)")
		ok_before = _authority_request_share(cfg=cfg, key_id=key_id, client_id=client_id, nonce=replay_nonce)
		if ok_before.get("status") != "ok":
			raise RuntimeError(f"expected ok before replay, got: {ok_before}")
		denied_after = _authority_request_share(cfg=cfg, key_id=key_id, client_id=client_id, nonce=replay_nonce)
		if denied_after.get("status") != "denied":
			raise RuntimeError(f"expected denied after replay, got: {denied_after}")
		if denied_after.get("denial_reason") != "revoked":
			raise RuntimeError(f"expected denial_reason=revoked, got: {denied_after.get('denial_reason')}")
		if denied_after.get("key_status") != "DESTROYED":
			raise RuntimeError(f"expected key_status=DESTROYED, got: {denied_after.get('key_status')}")
		log.info("Key destruction observed: key_status=%s", denied_after.get("key_status"))

		# Assert revocation happens exactly once: destroy_key must now be idempotent.
		destroy_resp = _authority_destroy_key(
			cfg=cfg,
			key_id=key_id,
			client_id=client_id,
			nonce=secrets.token_urlsafe(32),
			reason="demo_assert_idempotent",
		)
		if destroy_resp.get("key_status") != "DESTROYED":
			raise RuntimeError(f"expected DESTROYED after revocation, got: {destroy_resp}")
		if destroy_resp.get("destroyed") is not False:
			raise RuntimeError(f"expected destroyed=false (already revoked), got: {destroy_resp}")

		# Attempt decryption again; must fail permanently.
		log.info("Attempting decryption after revocation (must fail irreversibly)")
		failures = 0
		for attempt in range(1, 4):
			resp = _authority_request_share(cfg=cfg, key_id=key_id, client_id=client_id, nonce=secrets.token_urlsafe(32))
			if resp.get("status") != "denied":
				raise RuntimeError(f"unexpectedly obtained authority share after revocation: {resp}")
			if resp.get("denial_reason") != "revoked" or resp.get("key_status") != "DESTROYED":
				raise RuntimeError(f"unexpected denial structure after revocation: {resp}")
			failures += 1
			log.info(
				"Decryption blocked (attempt=%d): denial_reason=%s key_status=%s",
				attempt,
				resp.get("denial_reason"),
				resp.get("key_status"),
			)

		if failures != 3:
			raise RuntimeError("revocation was not permanent")

		log.info("Permanent failure proven: no retries can recover the share")

		try:
			delete_object(object_id)
			log.info("Deleted encrypted blob from storage")
		except StorageError:
			pass

	finally:
		log.info("Stopping authority service")
		server.stop()


if __name__ == "__main__":
	run_demo()

