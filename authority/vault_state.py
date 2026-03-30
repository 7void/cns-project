from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Dict, List, Optional


def _utcnow() -> datetime:
	return datetime.now(timezone.utc)


@dataclass
class Client:
	client_id: str
	name: str
	password_hash: str
	client_pubkey_b64: str
	registered_at: datetime


@dataclass
class FileRecord:
	file_id: str
	filename: str
	uploader_id: str
	authorized_clients: List[str]
	object_id: str
	key_id: str
	created_at: datetime
	status: str


@dataclass(frozen=True)
class AccessLog:
	timestamp: datetime
	client_id: str
	file_id: str
	result: str
	reason: str


@dataclass(frozen=True)
class Metrics:
	total_files: int
	active_files: int
	destroyed_files: int
	expired_files: int
	total_access_requests: int
	denied_requests: int


class VaultState:
	"""In-memory metadata store for a multi-client vault demo."""

	def __init__(self) -> None:
		self._lock = RLock()
		self._clients: Dict[str, Client] = {}
		self._files: Dict[str, FileRecord] = {}
		self._access_logs: List[AccessLog] = []
		self._total_access_requests = 0
		self._denied_requests = 0

	def register_client(self, *, name: str, password: str, client_pubkey_b64: str) -> Client:
		if not name:
			raise ValueError("name is required")
		if not password:
			raise ValueError("password is required")
		if not client_pubkey_b64:
			raise ValueError("client_pubkey_b64 is required")
		with self._lock:
			existing = [c for c in self._clients.values() if c.name == name]
			if existing:
				raise ValueError(f"client name '{name}' already registered")
			import hashlib
			password_hash = hashlib.sha256(password.encode()).hexdigest()
			client_id = f"client-{uuid.uuid4()}"
			client = Client(
				client_id=client_id,
				name=name,
				password_hash=password_hash,
				client_pubkey_b64=client_pubkey_b64,
				registered_at=_utcnow(),
			)
			self._clients[client_id] = client
			return client

	def list_clients(self) -> List[Client]:
		with self._lock:
			return list(self._clients.values())

	def login(self, *, name: str, password: str, client_pubkey_b64: str) -> Client:
		if not name or not password or not client_pubkey_b64:
			raise ValueError("name, password, and client_pubkey_b64 are required")
		password_hash = hashlib.sha256(password.encode()).hexdigest()
		with self._lock:
			for client in self._clients.values():
				if client.name == name and client.password_hash == password_hash:
					if client.client_pubkey_b64 != client_pubkey_b64:
						raise ValueError("device key mismatch")
					return client
			raise ValueError("invalid name or password")

	def get_client(self, client_id: str) -> Optional[Client]:
		with self._lock:
			return self._clients.get(client_id)

	def register_file(
		self,
		*,
		file_id: str,
		filename: str,
		uploader_id: str,
		authorized_clients: List[str],
		object_id: str,
		key_id: str,
		status: str = "ACTIVE",
	) -> FileRecord:
		if not file_id:
			raise ValueError("file_id is required")
		if not filename:
			raise ValueError("filename is required")
		if not uploader_id:
			raise ValueError("uploader_id is required")
		if not object_id:
			raise ValueError("object_id is required")
		if not key_id:
			raise ValueError("key_id is required")
		if not authorized_clients:
			raise ValueError("authorized_clients must be non-empty")

		record = FileRecord(
			file_id=file_id,
			filename=filename,
			uploader_id=uploader_id,
			authorized_clients=list(dict.fromkeys(authorized_clients)),
			object_id=object_id,
			key_id=key_id,
			created_at=_utcnow(),
			status=status,
		)
		with self._lock:
			self._files[file_id] = record
			return record

	def list_files(self) -> List[FileRecord]:
		with self._lock:
			return list(self._files.values())

	def get_file(self, file_id: str) -> Optional[FileRecord]:
		with self._lock:
			return self._files.get(file_id)

	def find_file_by_key_id(self, key_id: str) -> Optional[FileRecord]:
		with self._lock:
			for record in self._files.values():
				if record.key_id == key_id:
					return record
			return None

	def set_file_status_by_key_id(self, *, key_id: str, status: str) -> None:
		with self._lock:
			for record in self._files.values():
				if record.key_id == key_id:
					record.status = status

	def log_access(self, *, client_id: str, file_id: str, result: str, reason: str) -> None:
		with self._lock:
			self._total_access_requests += 1
			if result != "SUCCESS":
				self._denied_requests += 1
			self._access_logs.append(
				AccessLog(timestamp=_utcnow(), client_id=client_id, file_id=file_id, result=result, reason=reason)
			)

	def list_access_logs(self) -> List[AccessLog]:
		with self._lock:
			return list(self._access_logs)

	def metrics(self) -> Metrics:
		with self._lock:
			files = list(self._files.values())
			total_files = len(files)
			active_files = sum(1 for f in files if f.status == "ACTIVE")
			destroyed_files = sum(1 for f in files if f.status == "DESTROYED")
			expired_files = sum(1 for f in files if f.status == "EXPIRED")
			return Metrics(
				total_files=total_files,
				active_files=active_files,
				destroyed_files=destroyed_files,
				expired_files=expired_files,
				total_access_requests=self._total_access_requests,
				denied_requests=self._denied_requests,
			)
