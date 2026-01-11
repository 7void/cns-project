import streamlit as st
import requests
import uuid

st.set_page_config(page_title="Key Authority", layout="centered")

AUTHORITY_URL = "http://172.21.16.1:8000"

st.title("🔐 Key Authority Console")

key_id = st.text_input(
    "Key ID",
    value=st.session_state.get("key_id", f"demo-key-{uuid.uuid4()}")
)

st.session_state["key_id"] = key_id

if st.button("🧨 DESTROY KEY", type="primary"):
    try:
        resp = requests.post(
            f"{AUTHORITY_URL}/destroy_key",
            json={
                "key_id": key_id,
                "client_id": "authority-ui",
                "nonce": str(uuid.uuid4()),
                "reason": "manual_demo_destruction"
            },
            timeout=5
        )
        st.subheader("Authority Response")
        st.json(resp.json())
    except Exception as e:
        st.error(str(e))
