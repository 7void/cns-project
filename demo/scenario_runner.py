from __future__ import annotations

import base64
import json
import logging
import secrets
import threading
import time
import os
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
	authority_base_url: str = os.getenv("AUTHORITY_BASE_URL", "http://10.129.47.110:8000")
	http_timeout_seconds: float = 5.0
	# Keep the authority share alive long enough for a live multi-laptop demo.
	expires_in_seconds: int = 24 * 60 * 60


class AuthorityServer:
	def __init__(self, host: str = "0.0.0.0", port: int = 8000) -> None:
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

	start_local_authority = os.getenv("DEMO_START_LOCAL_AUTHORITY", "0").strip().lower() in {"1", "true", "yes", "y", "on"}
	if start_local_authority:
		log.info("Starting authority service (binding to 0.0.0.0 for LAN access)")
		server.start()
	try:
		_wait_for_authority(cfg)

		key_id = f"demo-key-{uuid.uuid4()}"
		object_id = f"demo-object-{uuid.uuid4()}"
		client_id = f"client-{uuid.uuid4()}"

		# One-time setup
		plaintext = b"Confidential: live demo object (encrypted client-side)"
		log.info("Generated plaintext (len=%d)", len(plaintext))

		master_key = aes.generate_key()
		master_key_buf = bytearray(master_key)
		log.info("Generated AES-256 master key (not logged)")

		client_share: bytes
		authority_share: bytes
		try:
			shares = shamir.split(master_key, t=2, n=3)
			client_share = shares[0]
			authority_share = shares[1]
			unused_share = shares[2]
			best_effort_wipe(bytearray(unused_share))
			log.info("Split master key with Shamir (t=2, n=3)")

			_authority_register_share(cfg=cfg, key_id=key_id, client_id=client_id, authority_share=authority_share)
			log.info("Registered authority share")
		finally:
			best_effort_wipe(master_key_buf)

		# Encrypt & upload (no authority requests; just local reconstruction for setup)
		reconstructed_master = shamir.combine([client_share, authority_share])
		reconstructed_master_buf = bytearray(reconstructed_master)
		derived_key_buf: Optional[bytearray] = None
		try:
			kdf_nonce = random_bytes(16)
			derived_key = kdf.derive(reconstructed_master, context=_context_for_kdf(client_id=client_id, nonce=kdf_nonce))
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
			best_effort_wipe(reconstructed_master_buf)
			best_effort_wipe(derived_key_buf)

		# Output required values for the live multi-laptop demo.
		client_share_b64 = _b64e(client_share)
		print("\n=== LIVE DEMO SETUP OUTPUT ===")
		print("KEY_ID        =", key_id)
		print("OBJECT_ID     =", object_id)
		print("CLIENT_ID     =", client_id)
		print("CLIENT_SHARE  =", client_share_b64)
		print("==============================\n")
		print("Setup complete. Authority is running and will stay alive for the live demo.")
		print("Authority binds to 0.0.0.0:8000 (LAN-accessible).")
		print("Press Ctrl+C to stop this script when you're done.\n")

		# Long-running mode: do NOT trigger attacks, revocation, teardown, or shutdown.
		while True:
			time.sleep(3600)

	except KeyboardInterrupt:
		log.info("Received Ctrl+C; stopping authority service")
		if start_local_authority:
			server.stop()
		return
	except Exception:
		log.exception("Setup failed; stopping authority service")
		server.stop()
		raise


if __name__ == "__main__":
	run_demo()

