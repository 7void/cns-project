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
AUTHORITY_URL = "http://10.129.47.110:8000"

KEY_ID        = "demo-key-84b0dffc-80c5-4a03-bd77-8455389fec90"
OBJECT_ID     = "demo-object-f8816fd4-6a22-4e48-8a8d-038e3a61a8b1"
CLIENT_ID     = "client-c7540e26-269f-42f3-9a58-6248f0d59938"
CLIENT_SHARE_B64  = "AZfwGzHHEObazTbRoqfjF0SZTDuECfXze7HVlmW3ijzW"
# ==========================================

st.set_page_config(page_title="Client / Hacker", layout="centered")
st.title("🧑‍💻 Client / Hacker Console")

if "client_share" not in st.session_state:
    st.session_state["client_share"] = base64.b64decode(CLIENT_SHARE_B64)

if st.button("📂 ACCESS CONFIDENTIAL FILE"):
    try:
        st.write("STEP 1: Requesting authority share")

        nonce = str(uuid.uuid4())
        resp = requests.post(
            f"{AUTHORITY_URL}/request_share",
            json={
                "key_id": KEY_ID,
                "client_id": CLIENT_ID,
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

        blob = download_object(OBJECT_ID)

        st.write("STEP 4: Decrypting payload")

        envelope = json.loads(blob.decode())
        kdf_nonce = base64.b64decode(envelope["kdf_nonce_b64"])
        derived_key = kdf.derive(
            master_key,
            context=CLIENT_ID.encode() + b"|" + kdf_nonce
        )

        plaintext = aes.decrypt(envelope["aes"], derived_key)

        st.success("✅ ACCESS GRANTED")
        st.code(plaintext.decode())

    except Exception:
        st.error("⚠️ ERROR (full traceback below)")
        st.code(traceback.format_exc())