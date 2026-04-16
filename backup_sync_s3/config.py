from backup_sync_s3.settings import EnvVar, require_env_var

REMOTE_FILE_LIST = "files.lst"
CSV_CELL_DELIMITER = ";"
INCOMPLETE_BACKUP_PREFIX = "INCOMPLETE_"
TMP_DIR_PATH = "/tmp"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
ENCODING = "utf-8"

# Multipart thresholds — files above MULTIPART_THRESHOLD are uploaded/downloaded
# in MULTIPART_CHUNK_SIZE pieces using multiple threads; files are never fully
# read into memory at any point.
MULTIPART_THRESHOLD = 100 * 1024 * 1024   # 100 MB
MULTIPART_CHUNK_SIZE = 8 * 1024 * 1024    # 8 MB per part
MULTIPART_MAX_CONCURRENCY = 4             # parallel threads per transfer

# Block size used when streaming files through the MD5 hasher.
HASH_CHUNK_SIZE = 4 * 1024 * 1024         # 4 MB

S3_BUCKET_NAME = require_env_var(EnvVar.S3_BUCKET_NAME)
S3_ENDPOINT_URL = require_env_var(EnvVar.S3_ENDPOINT_URL)
S3_REGION = require_env_var(EnvVar.S3_REGION)
S3_ACCESS_KEY = require_env_var(EnvVar.S3_ACCESS_KEY)
S3_SECRET_KEY = require_env_var(EnvVar.S3_SECRET_KEY)
BACKUP_LIST_PATH = require_env_var(EnvVar.BACKUP_LIST_PATH)

