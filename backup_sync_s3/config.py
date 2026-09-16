import os
from enum import StrEnum

# Multipart thresholds — files above MULTIPART_THRESHOLD are uploaded/downloaded
# in MULTIPART_CHUNK_SIZE pieces using multiple threads; files are never fully
# read into memory at any point.
MULTIPART_THRESHOLD = 500 * 1024**2
MULTIPART_CHUNK_SIZE = 50 * 1024**2

DEFAULT_MAX_THREAD_COUNT_FOR_UPLOAD = 6
REMOTE_FILE_LIST = "files.lst"
CSV_CELL_DELIMITER = ";"
INCOMPLETE_BACKUP_PREFIX = "INCOMPLETE_"
TMP_DIR_PATH = "/tmp"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
ENCODING = "utf-8"


class EnvVar(StrEnum):
    S3_BUCKET_NAME = "S3_BUCKET_NAME"
    S3_ENDPOINT_URL = "S3_ENDPOINT_URL"
    S3_REGION = "S3_REGION"
    S3_ACCESS_KEY = "S3_ACCESS_KEY"
    S3_SECRET_KEY = "S3_SECRET_KEY"
    BACKUP_LIST_PATH = "BACKUP_LIST_PATH"
    MAX_THREAD_COUNT = "MAX_THREAD_COUNT"
    SYNC_RUN_INTERVAL = "SYNC_RUN_INTERVAL"
    USE_HASH_FOR_COMPARISON = "USE_HASH_FOR_COMPARISON"


class SyncInterval(StrEnum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


def require_env_var(name: str) -> str:
    if not (value := os.environ.get(name)):
        raise EnvironmentError(f"Environment variable {name} is required but not set.")
    return value


def parse_bool_env_var(name: str, default: bool = False) -> bool:
    if not (value := os.environ.get(name)):
        return default
    return value.lower() in ("true", "1")


MULTIPART_MAX_CONCURRENCY = int(os.environ.get(EnvVar.MAX_THREAD_COUNT, DEFAULT_MAX_THREAD_COUNT_FOR_UPLOAD))
S3_BUCKET_NAME = require_env_var(EnvVar.S3_BUCKET_NAME)
S3_ENDPOINT_URL = require_env_var(EnvVar.S3_ENDPOINT_URL)
S3_REGION = require_env_var(EnvVar.S3_REGION)
S3_ACCESS_KEY = require_env_var(EnvVar.S3_ACCESS_KEY)
S3_SECRET_KEY = require_env_var(EnvVar.S3_SECRET_KEY)
BACKUP_LIST_PATH = require_env_var(EnvVar.BACKUP_LIST_PATH)
SYNC_RUN_INTERVAL = SyncInterval(require_env_var(EnvVar.SYNC_RUN_INTERVAL))
USE_HASH_FOR_COMPARISON = parse_bool_env_var(EnvVar.USE_HASH_FOR_COMPARISON, default=False)
