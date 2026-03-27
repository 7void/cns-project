from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Optional

import requests
import urllib3
from fastapi import FastAPI, Request
from pydantic import BaseModel, Field

# Suppress InsecureRequestWarning when posting to authority over self-signed HTTPS.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("canary_service")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CANARY_SECRET: str = os.getenv("CANARY_SECRET", "canary-secret-dev")
AUTHORITY_BASE_URL: str = os.getenv("AUTHORITY_BASE_URL", "http://127.0.0.1:8000")


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------


@dataclass
class CanaryRecord:
    key_id: str
    client_id: str
    canary_share_b64: str
    registered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


_lock: RLock = RLock()
_records: dict[str, CanaryRecord] = {}


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="Canary Service", version="1.0")


@app.on_event("startup")
async def _startup_warning() -> None:
    logger.warning(
        "Canary service started fresh — all previously registered canary shares are lost. "
        "Re-provision any active keys."
    )


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RegisterCanaryRequest(BaseModel):
    key_id: str = Field(..., min_length=1)
    client_id: str = Field(..., min_length=1)
    canary_share_b64: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Helper — fire alert to authority (runs in a daemon thread to avoid blocking)
# ---------------------------------------------------------------------------


def _fire_canary_alert_sync(
    *,
    key_id: str,
    requester_id: Optional[str],
    requester_ip: str,
) -> None:
    """Send a canary alert to the authority service (synchronous, runs in a thread)."""
    url = f"{AUTHORITY_BASE_URL.rstrip('/')}/canary_alert"
    payload: dict[str, Any] = {
        "key_id": key_id,
        "requester_id": requester_id,
        "requester_ip": requester_ip,
    }
    headers = {"X-Canary-Secret": CANARY_SECRET}
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=5.0, verify=False)
        logger.info(
            "Canary alert sent for key_id=%s — authority responded HTTP %s",
            key_id,
            resp.status_code,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Failed to send canary alert to authority for key_id=%s: %s",
            key_id,
            exc,
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post("/register_canary")
async def register_canary(body: RegisterCanaryRequest) -> dict[str, str]:
    """Store a canary share for the given key_id.

    Called by the client during key provisioning to deposit Share 3.
    """
    with _lock:
        _records[body.key_id] = CanaryRecord(
            key_id=body.key_id,
            client_id=body.client_id,
            canary_share_b64=body.canary_share_b64,
        )
    logger.info("Canary share registered for key_id=%s", body.key_id)
    return {"status": "ok"}


@app.get("/request_canary_share")
async def request_canary_share(
    request: Request,
    key_id: str,
    requester_id: Optional[str] = None,
) -> dict[str, Any]:
    """Honeypot endpoint — return the canary share while silently alerting the authority.

    The requester (potential attacker) receives the real canary share and sees no
    indication that an alert has been fired.  The authority is alerted asynchronously
    so this response is not delayed.
    """
    with _lock:
        record = _records.get(key_id)

    if record is None:
        return {"status": "not_found"}

    requester_ip: str = (
        request.client.host if request.client else "unknown"
    )
    timestamp: str = datetime.now(timezone.utc).isoformat()

    logger.warning(
        "CANARY TRIPWIRE TRIGGERED — key_id=%s requester_id=%s ip=%s at %s",
        key_id,
        requester_id,
        requester_ip,
        timestamp,
    )

    # Fire the alert in a daemon thread — do NOT await so the attacker's response
    # is not delayed and they cannot detect the alert by observing timing.
    alert_thread = threading.Thread(
        target=_fire_canary_alert_sync,
        kwargs={
            "key_id": key_id,
            "requester_id": requester_id,
            "requester_ip": requester_ip,
        },
        daemon=True,
        name=f"canary-alert-{key_id[:8]}",
    )
    alert_thread.start()

    # Return the real canary share — attacker sees a normal response.
    return {"status": "ok", "canary_share_b64": record.canary_share_b64}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
