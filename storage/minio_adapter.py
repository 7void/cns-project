from __future__ import annotations

import os
from dataclasses import dataclass
from io import BytesIO
from typing import Optional

from minio import Minio
from minio.error import S3Error


class StorageError(RuntimeError):
	"""Raised when storage operations fail."""


def _env(name: str, default: Optional[str] = None) -> str:
	val = os.getenv(name)
	if val is None or val == "":
		if default is None:
			raise StorageError(f"Missing required environment variable: {name}")
		return default
	return val


def _env_bool(name: str, default: bool = False) -> bool:
	raw = os.getenv(name)
	if raw is None or raw == "":
		return default
	return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class MinioConfig:
	endpoint: str
	access_key: str
	secret_key: str
	bucket: str
	secure: bool


_client: Optional[Minio] = None
_bucket: Optional[str] = None


def _get_client() -> tuple[Minio, str]:
	global _client, _bucket
	if _client is not None and _bucket is not None:
		return _client, _bucket

	cfg = MinioConfig(
		endpoint=_env("MINIO_ENDPOINT", "localhost:9000"),
		access_key=_env("MINIO_ACCESS_KEY"),
		secret_key=_env("MINIO_SECRET_KEY"),
		bucket=_env("MINIO_BUCKET", "cns-project"),
		secure=_env_bool("MINIO_SECURE", False),
	)

	client = Minio(
		cfg.endpoint,
		access_key=cfg.access_key,
		secret_key=cfg.secret_key,
		secure=cfg.secure,
	)

	try:
		if not client.bucket_exists(cfg.bucket):
			client.make_bucket(cfg.bucket)
	except S3Error as exc:
		raise StorageError(f"Failed to ensure bucket exists: {exc}") from exc
	except Exception as exc:  # noqa: BLE001
		raise StorageError(f"Failed to initialize MinIO client: {exc}") from exc

	_client = client
	_bucket = cfg.bucket
	return client, cfg.bucket


def upload_object(object_id: str, payload: bytes) -> None:
	"""Upload an encrypted blob.

	Storage is treated as untrusted; callers must only provide encrypted bytes.
	"""
	if not object_id:
		raise ValueError("object_id is required")
	if not isinstance(payload, (bytes, bytearray)):
		raise TypeError("payload must be bytes")

	client, bucket = _get_client()
	data = bytes(payload)
	stream = BytesIO(data)
	try:
		client.put_object(
			bucket_name=bucket,
			object_name=object_id,
			data=stream,
			length=len(data),
			content_type="application/octet-stream",
		)
	except S3Error as exc:
		raise StorageError(f"upload_object failed: {exc}") from exc
	except Exception as exc:  # noqa: BLE001
		raise StorageError(f"upload_object failed: {exc}") from exc


def download_object(object_id: str) -> bytes:
	"""Download an encrypted blob."""
	if not object_id:
		raise ValueError("object_id is required")

	client, bucket = _get_client()
	resp = None
	try:
		resp = client.get_object(bucket_name=bucket, object_name=object_id)
		return resp.read()
	except S3Error as exc:
		raise StorageError(f"download_object failed: {exc}") from exc
	except Exception as exc:  # noqa: BLE001
		raise StorageError(f"download_object failed: {exc}") from exc
	finally:
		try:
			if resp is not None:
				resp.close()
				resp.release_conn()
		except Exception:
			pass


def delete_object(object_id: str) -> None:
	"""Delete an encrypted blob."""
	if not object_id:
		raise ValueError("object_id is required")

	client, bucket = _get_client()
	try:
		client.remove_object(bucket_name=bucket, object_name=object_id)
	except S3Error as exc:
		raise StorageError(f"delete_object failed: {exc}") from exc
	except Exception as exc:  # noqa: BLE001
		raise StorageError(f"delete_object failed: {exc}") from exc

