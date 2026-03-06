import os
import sys
import traceback
import uuid

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st
import requests
import base64
import json
from typing import Any

from crypto import aes, kdf, shamir
from crypto.utils import best_effort_wipe, random_bytes
from storage.minio_adapter import StorageError, download_object, upload_object

DEFAULT_AUTHORITY_URL = os.getenv("AUTHORITY_BASE_URL", "http://127.0.0.1:8000")


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64, validate=True)


def _device_key_path(client_id: str) -> str:
    return os.path.join(PROJECT_ROOT, "client", "device_keys", f"{client_id}.json")


def _load_local_client_share(client_id: str) -> bytes | None:
    path = _device_key_path(client_id)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        share_b64 = str(data.get("client_share_b64") or "")
        return _b64d(share_b64) if share_b64 else None
    except Exception:
        return None


def _save_local_client_share(client_id: str, client_share: bytes) -> None:
    os.makedirs(os.path.dirname(_device_key_path(client_id)), exist_ok=True)
    with open(_device_key_path(client_id), "w", encoding="utf-8") as f:
        json.dump({"client_id": client_id, "client_share_b64": _b64e(client_share)}, f)


def _post_json(url: str, payload: dict[str, Any], timeout_s: float = 10.0) -> dict[str, Any]:
    resp = requests.post(url, json=payload, timeout=timeout_s)
    try:
        return resp.json()
    except Exception as exc:
        raise RuntimeError(f"Non-JSON response from authority: HTTP {resp.status_code}") from exc


def _get_json(url: str, timeout_s: float = 10.0) -> dict[str, Any]:
    resp = requests.get(url, timeout=timeout_s)
    try:
        return resp.json()
    except Exception as exc:
        raise RuntimeError(f"Non-JSON response from authority: HTTP {resp.status_code}") from exc

st.set_page_config(page_title="Client Vault", layout="centered")
st.title("🧑‍💻 Client Vault")

if "authority_url" not in st.session_state:
    st.session_state["authority_url"] = DEFAULT_AUTHORITY_URL
if "client_id" not in st.session_state:
    st.session_state["client_id"] = ""
if "client_name" not in st.session_state:
    st.session_state["client_name"] = ""
if "client_share" not in st.session_state:
    st.session_state["client_share"] = None
if "files" not in st.session_state:
    st.session_state["files"] = []
if "all_clients" not in st.session_state:
	st.session_state["all_clients"] = []

authority_url = st.text_input("Authority URL", value=st.session_state["authority_url"])
st.session_state["authority_url"] = authority_url
authority_base = authority_url.rstrip("/")

if not st.session_state.get("client_id"):
	st.header("Login")
	col1, col2 = st.columns(2)
	with col1:
		name = st.text_input("Username", placeholder="e.g. Alice")
		password = st.text_input("Password", type="password", placeholder="your password")
		if st.button("🔐 Login"):
			try:
				resp = _post_json(f"{authority_base}/login", {"name": name, "password": password})
				client_id = str(resp.get("client_id") or "")
				client_name = str(resp.get("name") or "")
				if not client_id:
					raise RuntimeError(f"login failed: {resp}")
				st.session_state["client_id"] = client_id
				st.session_state["client_name"] = client_name
				share = _load_local_client_share(client_id)
				if share:
					st.session_state["client_share"] = share
				st.success(f"Logged in as {client_name}")
				st.rerun()
			except Exception:
				st.error("Login failed (invalid name or password)")
	with col2:
		st.subheader("New user?")
		new_name = st.text_input("Username", placeholder="e.g. Bob", key="reg_name")
		new_password = st.text_input("Password", type="password", placeholder="your password", key="reg_pass")
		if st.button("✅ Register"):
			try:
				resp = _post_json(f"{authority_base}/register_client", {"name": new_name, "password": new_password})
				client_id = str(resp.get("client_id") or "")
				if not client_id:
					raise RuntimeError(f"register failed: {resp}")
				st.session_state["client_id"] = client_id
				st.session_state["client_name"] = new_name
				st.success(f"Registered as {new_name}. Logging in...")
				st.rerun()
			except Exception:
				st.error("Registration failed")
				st.code(traceback.format_exc())
	st.stop()

st.header(f"Welcome, {st.session_state['client_name']}")
if st.button("🚪 Logout"):
	st.session_state["client_id"] = ""
	st.session_state["client_name"] = ""
	st.session_state["client_share"] = None
	st.success("Logged out")
	st.rerun()

st.header("Client Share")
import_share_b64 = st.text_input("Import share (base64)", value="", placeholder="Paste client share b64 from collaborator")
if st.button("💾 Save Imported Share"):
	try:
		share = _b64d(import_share_b64.strip())
		st.session_state["client_share"] = share
		_save_local_client_share(st.session_state["client_id"], share)
		st.success("Saved client share locally")
	except Exception:
		st.error("Failed to save imported share")
		st.code(traceback.format_exc())

st.header("Upload File")
if st.button("🔄 Refresh Available Clients"):
	try:
		all_clients = _get_json(f"{authority_base}/clients")
		if not isinstance(all_clients, list):
			raise RuntimeError("/clients returned unexpected response")
		st.session_state["all_clients"] = all_clients
		st.success(f"Loaded {len(all_clients)} registered clients")
	except Exception:
		st.error("Failed to refresh clients")
		st.code(traceback.format_exc())

uploaded = st.file_uploader("Choose a file", type=None)

st.subheader("Grant Access To")
all_clients = st.session_state.get("all_clients") or []
other_clients = [c for c in all_clients if c["client_id"] != st.session_state["client_id"]]
selected_clients = st.multiselect(
	"Select which clients can decrypt this file",
	options=other_clients,
	format_func=lambda c: f"{c['name']} ({c['client_id']})",
)

if st.button("⬆️ Encrypt + Upload + Register"):
	try:
		if uploaded is None:
			raise RuntimeError("Choose a file first")
		uploader_id = (st.session_state.get("client_id") or "").strip()
		if not uploader_id:
			raise RuntimeError("Not logged in")
		authorized_clients = [c["client_id"] for c in selected_clients]
		if not authorized_clients:
			raise RuntimeError("Select at least one authorized client")

		plaintext = uploaded.getvalue()
		filename = uploaded.name or "uploaded.bin"

		master_key = aes.generate_key()
		master_key_buf = bytearray(master_key)
		derived_key_buf: bytearray | None = None
		try:
			shares = shamir.split(master_key, t=2, n=3)
			client_share = shares[0]
			authority_share = shares[1]
			best_effort_wipe(bytearray(shares[2]))

			_save_local_client_share(uploader_id, client_share)
			st.session_state["client_share"] = client_share

			key_id = f"key-{uuid.uuid4()}"
			object_id = f"object-{uuid.uuid4()}"
			kdf_nonce = random_bytes(16)
			derived_key = kdf.derive(master_key, context=uploader_id.encode("utf-8") + b"|" + kdf_nonce)
			derived_key_buf = bytearray(derived_key)

			aes_payload = aes.encrypt(plaintext, key=derived_key)
			envelope = {
				"key_id": key_id,
				"client_id": uploader_id,
				"kdf_nonce_b64": _b64e(kdf_nonce),
				"aes": aes_payload,
				"filename": filename,
			}
			blob = json.dumps(envelope).encode("utf-8")
			upload_object(object_id, blob)
		finally:
			best_effort_wipe(master_key_buf)
			best_effort_wipe(derived_key_buf)

		resp = _post_json(
			f"{authority_base}/register_file",
			{
				"filename": filename,
				"uploader_id": uploader_id,
				"authorized_clients": authorized_clients,
				"key_id": key_id,
				"object_id": object_id,
				"authority_share_b64": _b64e(authority_share),
			},
		)
		file_id = str(resp.get("file_id") or "")
		if not file_id:
			raise RuntimeError(f"register_file failed: {resp}")

		st.success(f"Uploaded and registered file_id={file_id}")
		st.info("💡 If you granted access to other clients, they can now decrypt this file. Their client apps can import your share (base64) by using the 'Import share' field on their UI.")
		st.code(_b64e(client_share))
	except StorageError as exc:
		st.error(f"MinIO error: {exc}")
	except Exception:
		st.error("Upload failed")
		st.code(traceback.format_exc())


st.header("Files")
colf1, colf2 = st.columns(2)
with colf1:
	if st.button("🔄 Refresh Accessible Files"):
		try:
			client_id = (st.session_state.get("client_id") or "").strip()
			if not client_id:
				raise RuntimeError("Set Client ID first")
			files = _get_json(f"{authority_base}/files?client_id={client_id}")
			if not isinstance(files, list):
				raise RuntimeError("/files returned unexpected response")
			st.session_state["files"] = files
		except Exception:
			st.error("Failed to refresh files")
			st.code(traceback.format_exc())
with colf2:
	st.caption("Shows files where you are authorized")

files = st.session_state.get("files") or []
options = [f"{f.get('filename')} ({f.get('file_id')})" for f in files]
if not options:
	st.info("No accessible files yet. Upload one or refresh.")
	selected = ""
else:
	selected = st.selectbox("Select a file", options=options)

if st.button("📂 Request Share + Decrypt"):
	try:
		client_id = (st.session_state.get("client_id") or "").strip()
		client_share = st.session_state.get("client_share")
		if not client_id or client_share is None:
			raise RuntimeError("Set Client ID and ensure you have a local client share")
		if not selected:
			raise RuntimeError("Select a file first")

		selected_file = None
		for f in files:
			if str(f.get("file_id")) in selected:
				selected_file = f
				break
		if not selected_file:
			raise RuntimeError("Could not resolve selected file")

		blob = download_object(str(selected_file["object_id"]))
		envelope = json.loads(blob.decode("utf-8"))
		if not isinstance(envelope, dict):
			raise RuntimeError("Stored envelope is not a JSON dict")

		resp = _post_json(
			f"{authority_base}/request_share",
			{
				"key_id": str(selected_file["key_id"]),
				"client_id": client_id,
				"file_id": str(selected_file["file_id"]),
				"nonce": str(uuid.uuid4()),
			},
			timeout_s=5.0,
		)
		st.write("Authority response:", resp)
		if resp.get("status") != "ok":
			raise RuntimeError(f"ACCESS DENIED (key_status={resp.get('key_status')}, reason={resp.get('denial_reason')})")

		authority_share = _b64d(str(resp["authority_share_b64"]))
		master_key = shamir.combine([client_share, authority_share])
		master_key_buf = bytearray(master_key)
		derived_key_buf: bytearray | None = None
		try:
			kdf_nonce = _b64d(str(envelope["kdf_nonce_b64"]))
			bound_client_id = str(envelope.get("client_id") or "")
			derived_key = kdf.derive(master_key, context=bound_client_id.encode("utf-8") + b"|" + kdf_nonce)
			derived_key_buf = bytearray(derived_key)
			plaintext = aes.decrypt(envelope["aes"], derived_key)
		finally:
			best_effort_wipe(master_key_buf)
			best_effort_wipe(derived_key_buf)

		st.success("✅ Decrypted")
		st.code(plaintext.decode("utf-8", errors="replace"))
	except Exception:
		st.error("Decrypt failed")
		st.code(traceback.format_exc())