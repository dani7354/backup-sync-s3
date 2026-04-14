import os
from enum import StrEnum


class EnvVar(StrEnum):
    S3_BUCKET_NAME = "S3_BUCKET_NAME"
    S3_ENDPOINT_URL = "S3_ENDPOINT_URL"
    S3_REGION = "S3_REGION"
    S3_ACCESS_KEY = "S3_ACCESS_KEY"
    S3_SECRET_KEY = "S3_SECRET_KEY"


def require_env_var(name: str) -> str:
    if not (value := os.environ.get(name)):
        raise EnvironmentError(f"Environment variable {name} is required but not set.")
    return value