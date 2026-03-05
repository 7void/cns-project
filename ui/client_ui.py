import os
import sys
import traceback

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st
import requests
import uuid
import base64
import json

from crypto import aes, kdf, shamir
from storage.minio_adapter import download_object

# ================= CONFIG =================
DEFAULT_AUTHORITY_URL = os.getenv("AUTHORITY_BASE_URL", "http://127.0.0.1:8000")

# Optional defaults (if you want the UI to boot with an existing session).
DEFAULT_KEY_ID = ""
DEFAULT_OBJECT_ID = ""
DEFAULT_CLIENT_ID = ""
DEFAULT_CLIENT_SHARE_B64 = ""
# ==========================================

st.set_page_config(page_title="Client / Hacker", layout="centered")
st.title("🧑‍💻 Client / Hacker Console")

if "authority_url" not in st.session_state:
    st.session_state["authority_url"] = DEFAULT_AUTHORITY_URL
if "key_id" not in st.session_state:
    st.session_state["key_id"] = DEFAULT_KEY_ID
if "object_id" not in st.session_state:
    st.session_state["object_id"] = DEFAULT_OBJECT_ID
if "client_id" not in st.session_state:
    st.session_state["client_id"] = DEFAULT_CLIENT_ID
if "client_share_b64" not in st.session_state:
    st.session_state["client_share_b64"] = DEFAULT_CLIENT_SHARE_B64
if "client_share" not in st.session_state:
    st.session_state["client_share"] = base64.b64decode(st.session_state["client_share_b64"]) if st.session_state["client_share_b64"] else None

authority_url = st.text_input("Authority URL", value=st.session_state["authority_url"])
st.session_state["authority_url"] = authority_url

col1, col2 = st.columns(2)
with col1:
    if st.button("🆕 CREATE DEMO SESSION"):
        try:
            authority_url = st.session_state["authority_url"].rstrip("/")
            resp = requests.post(
                f"{authority_url}/create_demo_session",
                json={},
                timeout=10,
            ).json()
            missing = [k for k in ("key_id", "object_id", "client_id", "client_share") if not resp.get(k)]
            if missing:
                raise RuntimeError(f"Missing fields from /create_demo_session: {missing} ({resp})")

            st.session_state["key_id"] = str(resp["key_id"])
            st.session_state["object_id"] = str(resp["object_id"])
            st.session_state["client_id"] = str(resp["client_id"])
            st.session_state["client_share_b64"] = str(resp["client_share"])
            st.session_state["client_share"] = base64.b64decode(st.session_state["client_share_b64"])
            st.success("Demo session created")
        except Exception:
            st.error("Failed to create demo session")
            st.code(traceback.format_exc())
with col2:
    st.caption("Use this if the key expired or was destroyed")

st.write(
    "Current session:",
    {
        "key_id": st.session_state["key_id"],
        "object_id": st.session_state["object_id"],
        "client_id": st.session_state["client_id"],
    },
)

if st.button("📂 ACCESS CONFIDENTIAL FILE"):
    try:
        if not st.session_state.get("key_id") or not st.session_state.get("object_id") or not st.session_state.get("client_id"):
            st.error("No active demo session. Click 'CREATE DEMO SESSION' first.")
            st.stop()
        if st.session_state.get("client_share") is None:
            st.error("Missing client share. Click 'CREATE DEMO SESSION' first.")
            st.stop()

        st.write("STEP 1: Requesting authority share")

        nonce = str(uuid.uuid4())
        authority_url = st.session_state["authority_url"].rstrip("/")
        resp = requests.post(
            f"{authority_url}/request_share",
            json={
                "key_id": st.session_state["key_id"],
                "client_id": st.session_state["client_id"],
                "nonce": nonce
            },
            timeout=5
        ).json()

        st.write("Authority response:", resp)

        if resp.get("status") != "ok":
            st.error(f"❌ ACCESS DENIED — key_status={resp.get('key_status')}")
            st.stop()

        st.write("STEP 2: Reconstructing master key")

        authority_share = base64.b64decode(resp["authority_share_b64"])
        client_share = st.session_state["client_share"]
        master_key = shamir.combine([client_share, authority_share])

        st.write("STEP 3: About to download object from MinIO")
        st.write("MINIO_ENDPOINT =", os.getenv("MINIO_ENDPOINT"))

        blob = download_object(st.session_state["object_id"])

        st.write("STEP 4: Decrypting payload")

        envelope = json.loads(blob.decode())
        kdf_nonce = base64.b64decode(envelope["kdf_nonce_b64"])
        derived_key = kdf.derive(
            master_key,
            context=st.session_state["client_id"].encode() + b"|" + kdf_nonce
        )

        plaintext = aes.decrypt(envelope["aes"], derived_key)

        st.success("✅ ACCESS GRANTED")
        st.code(plaintext.decode())

    except Exception:
        st.error("⚠️ ERROR (full traceback below)")
        st.code(traceback.format_exc())