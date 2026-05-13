"""
boto3_test.py – quick upload smoke-test for Linode object storage.

Usage:
    python boto3_test.py <local_file_path> [<s3_destination_key>]

If <s3_destination_key> is omitted the file is placed in the bucket root
using the original filename.

Required env vars (can be placed in a .env file):
    S3_BUCKET_NAME
    S3_ENDPOINT_URL   e.g. https://<cluster>.linodeobjects.com
    S3_REGION         e.g. eu-central-1
    S3_ACCESS_KEY
    S3_SECRET_KEY
"""

import logging
import os
import sys
import threading

import boto3
from boto3.s3.transfer import TransferConfig

# Load .env when python-dotenv is available (optional)
try:
    from dotenv import load_dotenv  # type: ignore[import]

    load_dotenv()
except ImportError:
    load_dotenv = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def configure_logging(level: int = logging.DEBUG) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logging.getLogger().setLevel(level)
    logging.getLogger().addHandler(handler)


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Progress callback
# ---------------------------------------------------------------------------


class ProgressCallback:
    """Thread-safe upload progress logger (identical pattern to s3.py)."""

    def __init__(self, filename: str, file_size: int) -> None:
        self._filename = filename
        self._file_size = file_size
        self._transferred = 0
        self._lock = threading.Lock()

    def __call__(self, bytes_amount: int) -> None:
        with self._lock:
            self._transferred += bytes_amount
            transferred = self._transferred

        if self._file_size > 0:
            pct = (transferred / self._file_size) * 100
            _logger.debug(
                "%s: %s / %s bytes (%.1f%%)",
                self._filename,
                f"{transferred:,}",
                f"{self._file_size:,}",
                pct,
            )


# ---------------------------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------------------------


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise EnvironmentError(f"Required environment variable '{name}' is not set.")
    return value


def build_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=_require_env("S3_ENDPOINT_URL"),
        region_name=_require_env("S3_REGION"),
        aws_access_key_id=_require_env("S3_ACCESS_KEY"),
        aws_secret_access_key=_require_env("S3_SECRET_KEY"),
    )


def upload_file(local_path: str, s3_key: str) -> None:
    bucket = _require_env("S3_BUCKET_NAME")
    client = build_s3_client()

    file_size = os.path.getsize(local_path)
    callback = ProgressCallback(os.path.basename(local_path), file_size)

    transfer_config = TransferConfig(
        multipart_threshold=100 * 1024 * 1024,  # 100 MB
        multipart_chunksize=8 * 1024 * 1024,  # 8 MB per part
        use_threads=True,
        max_concurrency=4,
    )

    _logger.info(
        "Uploading '%s' -> s3://%s/%s (%s bytes)",
        local_path,
        bucket,
        s3_key,
        f"{file_size:,}",
    )
    client.upload_file(
        local_path,
        bucket,
        s3_key,
        Config=transfer_config,
        Callback=callback,
    )
    _logger.info("Upload complete: s3://%s/%s", bucket, s3_key)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    configure_logging()

    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <local_file_path> [<s3_key>]")
        sys.exit(1)

    local_path = sys.argv[1]
    s3_key = sys.argv[2] if len(sys.argv) >= 3 else os.path.basename(local_path)

    if not os.path.isfile(local_path):
        _logger.error("File not found: %s", local_path)
        sys.exit(1)

    try:
        upload_file(local_path, s3_key)
    except EnvironmentError as e:
        _logger.error("Configuration error: %s", e)
        sys.exit(1)
    except Exception as e:
        _logger.exception("Upload failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
