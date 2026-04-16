import argparse
import logging
import pathlib

from dotenv import load_dotenv

from backup_sync_s3.sync import S3BackupSync
from backup_sync_s3.config import S3_BUCKET_NAME, S3_ENDPOINT_URL, S3_REGION, S3_ACCESS_KEY, S3_SECRET_KEY
from backup_sync_s3.s3 import S3Wrapper, S3Config

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


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="sync_s3.py", description="S3 Backup Sync (boto3)")
    parser.add_argument(
        "-l",
        "--backup-list-path",
        help="TXT file containing locations of backups to sync",
        dest="backup_list_path",
        type=pathlib.Path,
        required=True,
    )
    return parser.parse_args()


def _validate_and_get_backup_list(args: argparse.Namespace) -> pathlib.Path:
    if not (backups_path := args.backup_list_path) or not backups_path.is_file():
        raise FileNotFoundError(f"Backup directory list file {backups_path} not found!")
    return backups_path


def _get_s3_config() -> S3Config:
    return S3Config(
        bucket_name=S3_BUCKET_NAME,
        endpoint_url=S3_ENDPOINT_URL,
        region=S3_REGION,
        access_key=S3_ACCESS_KEY,
        secret_key=S3_SECRET_KEY)


def main() -> None:
    _configure_logging()
    try:
        load_dotenv()  # load .env file before reading any env vars
        args = _parse_arguments()
        backup_directory_list_path = _validate_and_get_backup_list(args)

        s3_config = _get_s3_config()
        s3 = S3Wrapper(s3_config)
        s3_backup_sync = S3BackupSync(s3, backup_directory_list_path)
        s3_backup_sync.run_backup_sync()
    except Exception:
        _logger.exception("Unexpected error during backup sync")

if __name__ == "__main__":
    main()

