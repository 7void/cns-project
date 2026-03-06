import os
import uuid

import requests
import streamlit as st

st.set_page_config(page_title="Authority Dashboard", layout="centered")

DEFAULT_AUTHORITY_URL = os.getenv("AUTHORITY_BASE_URL", "http://127.0.0.1:8000")
if "authority_url" not in st.session_state:
    st.session_state["authority_url"] = DEFAULT_AUTHORITY_URL

st.title("🔐 Authority Dashboard")

authority_url = st.text_input("Authority URL", value=st.session_state["authority_url"])
st.session_state["authority_url"] = authority_url
AUTHORITY_URL = authority_url.rstrip("/")


def _fetch_latest_key_id() -> str | None:
    try:
        resp = requests.get(f"{AUTHORITY_URL}/latest_key", timeout=3)
        data = resp.json() if resp.ok else {}
        key_id = data.get("key_id")
        return str(key_id) if key_id else None
    except Exception:
        return None


if "key_id" not in st.session_state or not st.session_state.get("key_id"):
    latest = _fetch_latest_key_id()
    if latest:
        st.session_state["key_id"] = latest

col1, col2 = st.columns(2)
with col1:
    if st.button("🔄 Load Latest Key"):
        latest = _fetch_latest_key_id()
        if latest:
            st.session_state["key_id"] = latest
            st.success("Loaded latest key_id")
        else:
            st.warning("No key registered yet")
with col2:
    st.caption("Use after a client registers a file")

st.header("Revoke")
key_id = st.text_input("Key ID", value=st.session_state.get("key_id", f"key-{uuid.uuid4()}"))

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


st.header("Metrics")
if st.button("📈 Refresh Metrics"):
	try:
		st.session_state["metrics"] = requests.get(f"{AUTHORITY_URL}/metrics", timeout=5).json()
	except Exception as exc:
		st.error(str(exc))

metrics = st.session_state.get("metrics")
if metrics:
	st.json(metrics)


st.header("File Inventory")
if st.button("📁 Refresh Files"):
	try:
		st.session_state["files"] = requests.get(f"{AUTHORITY_URL}/files", timeout=5).json()
	except Exception as exc:
		st.error(str(exc))

files = st.session_state.get("files")
if files:
	st.dataframe(files, use_container_width=True)


st.header("Access Logs")
if st.button("🧾 Refresh Logs"):
	try:
		st.session_state["logs"] = requests.get(f"{AUTHORITY_URL}/logs", timeout=5).json()
	except Exception as exc:
		st.error(str(exc))

logs = st.session_state.get("logs")
if logs:
	st.dataframe(logs, use_container_width=True)
