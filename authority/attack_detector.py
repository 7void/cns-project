from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Dict, Optional, Set

from .key_manager import KeyManager
from .storage import InMemoryStorage


def _utcnow() -> datetime:
	return datetime.now(timezone.utc)


@dataclass
class _NonceEntry:
	nonce: str
	timestamp: datetime


class AttackDetector:
	"""Detects basic security violations and triggers key destruction.

	Violations:
	- Replayed nonces (per key_id + client_id)
	- Duplicate/parallel requests for the same key_id
	- Unexpected client identifiers (mismatch with registered client_id)
	"""

	def __init__(
		self,
		*,
		key_manager: KeyManager,
		storage: InMemoryStorage,
		nonce_ttl_seconds: int = 600,
	) -> None:
		self._key_manager = key_manager
		self._storage = storage
		self._nonce_ttl = timedelta(seconds=int(nonce_ttl_seconds))

		self._nonce_lock = asyncio.Lock()
		# Track used nonces per (key_id, client_id) to prevent cross-client interference.
		self._seen_nonces: Dict[str, Dict[str, Dict[str, _NonceEntry]]] = {}

		self._inflight_lock = asyncio.Lock()
		self._inflight_keys: Set[str] = set()

	async def _record_nonce_or_violate(self, *, key_id: str, client_id: str, nonce: str) -> None:
		if not nonce:
			await self._violate(key_id=key_id, client_id=client_id, reason="missing_nonce")
			return

		now = _utcnow()
		window_start = now - self._nonce_ttl

		async with self._nonce_lock:
			by_key = self._seen_nonces.setdefault(key_id, {})
			by_client = by_key.setdefault(client_id, {})
			# opportunistic cleanup
			stale = [n for n, entry in by_client.items() if entry.timestamp < window_start]
			for n in stale:
				del by_client[n]

			if nonce in by_client:
				await self._violate(key_id=key_id, client_id=client_id, reason="replayed_nonce")
				return

			by_client[nonce] = _NonceEntry(nonce=nonce, timestamp=now)

	async def _ensure_expected_client_or_violate(self, *, key_id: str, client_id: str) -> None:
		expected = self._key_manager.get_registered_client_id(key_id)
		if expected is None:
			# Unknown key_id is handled by the service; do not destroy.
			return
		if client_id != expected:
			await self._violate(
				key_id=key_id,
				client_id=client_id,
				reason="unexpected_client_id",
			)

	async def _enter_inflight_or_violate(self, *, key_id: str, client_id: str) -> None:
		async with self._inflight_lock:
			if key_id in self._inflight_keys:
				await self._violate(key_id=key_id, client_id=client_id, reason="parallel_request")
				return
			self._inflight_keys.add(key_id)

	async def _exit_inflight(self, *, key_id: str) -> None:
		async with self._inflight_lock:
			self._inflight_keys.discard(key_id)

	async def _violate(self, *, key_id: str, client_id: Optional[str], reason: str) -> None:
		self._storage.append_audit_event(
			event_type="security_violation",
			key_id=key_id,
			client_id=client_id,
			details={"reason": reason},
		)
		# Destroy key share immediately.
		try:
			destroyed = self._key_manager.destroy_key(key_id, reason=f"security_violation:{reason}")
			# Ensure destruction is explicitly logged (even if already terminal).
			self._storage.append_audit_event(
				event_type="key_destruction_triggered",
				key_id=key_id,
				client_id=client_id,
				details={"reason": reason, "destroyed": destroyed},
			)
		except Exception:
			# Best-effort destruction; never raise attacker-controlled detail.
			pass

	@asynccontextmanager
	async def guard_request(
		self,
		*,
		key_id: str,
		client_id: str,
		nonce: str,
	) -> AsyncIterator[None]:
		"""Guard a request; destroys key on violations.

		The request handler should still perform its own authorization checks.
		"""
		await self._ensure_expected_client_or_violate(key_id=key_id, client_id=client_id)
		await self._record_nonce_or_violate(key_id=key_id, client_id=client_id, nonce=nonce)
		await self._enter_inflight_or_violate(key_id=key_id, client_id=client_id)
		try:
			yield
		finally:
			await self._exit_inflight(key_id=key_id)

