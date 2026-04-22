import argparse
import logging
import pathlib

from backup_sync_s3.s3 import S3Wrapper, S3Config
from backup_sync_s3.settings import require_env_var
from backup_sync_s3.sync import S3BackupSync
from backup_sync_s3.config import (
    S3_BUCKET_NAME, S3_ENDPOINT_URL, S3_REGION, S3_ACCESS_KEY, S3_SECRET_KEY, BACKUP_LIST_PATH)

_logger = logging.getLogger(__name__)
_logger.addHandler(logging.NullHandler())



def _configure_logging() -> None:
    """Configure the root logger with a single stream (console) handler."""
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)


def _validate_and_get_backup_list() -> pathlib.Path:
    backup_list_path = pathlib.Path(require_env_var(BACKUP_LIST_PATH))
    if not backup_list_path.is_file():
        raise FileNotFoundError(f"Backup directory list file {backup_list_path} not found!")

    return backup_list_path


def _get_s3_config() -> S3Config:
    return S3Config(
        bucket_name=S3_BUCKET_NAME,
        endpoint_url=S3_ENDPOINT_URL,
        region=S3_REGION,
        access_key=S3_ACCESS_KEY,
        secret_key=S3_SECRET_KEY)


def _get_backup_list_path() -> pathlib.Path:
    return pathlib.Path(BACKUP_LIST_PATH)


def main() -> None:
    _configure_logging()
    try:
        backup_directory_list_path = _validate_and_get_backup_list(args)

        s3_config = _get_s3_config()
        s3 = S3Wrapper(s3_config)
        s3_backup_sync = S3BackupSync(s3, backup_directory_list_path)
        s3_backup_sync.run_backup_sync()
    except Exception:
        _logger.exception("Unexpected error during backup sync")

if __name__ == "__main__":
    main()

