import dataclasses
import functools
import logging
import os
import threading
from datetime import datetime

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.exceptions import ClientError, BotoCoreError

from backup_sync_s3.config import MULTIPART_THRESHOLD, MULTIPART_CHUNK_SIZE, MULTIPART_MAX_CONCURRENCY


class S3CommandError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class S3Config:
    """All connection settings for an S3-compatible provider, read from env vars."""

    bucket_name: str
    endpoint_url: str
    region: str
    access_key: str
    secret_key: str


@dataclasses.dataclass(frozen=True)
class S3FileInfo:
    path: str
    size_gb: float
    uploaded: datetime


class ProgressCallback:
    """Callable passed to boto3 Callback= to log transfer progress.

    Thread-safe: boto3 invokes the callback from multiple threads concurrently
    when use_threads=True is set in TransferConfig (multipart transfers).
    """

    def __init__(self, filename: str, file_size: int) -> None:
        self._filename = filename
        self._file_size = file_size
        self._transferred = 0
        self._lock = threading.Lock()
        self._logger = logging.getLogger(self.__class__.__name__)

    def __call__(self, bytes_amount: int) -> None:
        with self._lock:
            self._transferred += bytes_amount
            transferred = self._transferred  # capture snapshot outside lock scope

        if self._file_size > 0:
            pct = (transferred / self._file_size) * 100
            self._logger.debug(
                "%s: %s / %s bytes (%.1f%%)",
                self._filename,
                f"{transferred:,}",
                f"{self._file_size:,}",
                pct,
            )

        if transferred >= self._file_size > 0:
            self._logger.info("Transfer of %s completed: %s bytes", self._filename, f"{self._file_size:,}")


class S3Wrapper:
    """Thin wrapper around the boto3 S3 client.

    Mirrors the interface of the original S3CmdWrapper so that S3BackupSync
    requires no changes. Large-file transfers are handled transparently via
    boto3's managed multipart upload/download — no full-file buffering occurs.
    """

    def __init__(self, config: S3Config) -> None:
        self._bucket_name = config.bucket_name
        self._client = boto3.client(
            "s3",
            endpoint_url=config.endpoint_url,
            region_name=config.region,
            aws_access_key_id=config.access_key,
            aws_secret_access_key=config.secret_key,
        )
        self._transfer_config = TransferConfig(
            multipart_threshold=MULTIPART_THRESHOLD,
            multipart_chunksize=MULTIPART_CHUNK_SIZE,
            use_threads=True,
            max_concurrency=MULTIPART_MAX_CONCURRENCY,
        )
        self._logger = logging.getLogger(self.__class__.__name__)

    class Decorator:
        @classmethod
        def catch_s3_error_and_raise(cls, func):
            @functools.wraps(func)
            def inner(self, *args, **kwargs):
                try:
                    return func(self, *args, **kwargs)
                except (BotoCoreError, ClientError) as e:
                    raise S3CommandError from e

            return inner

    @Decorator.catch_s3_error_and_raise
    def list_files(self, path: str) -> list[S3FileInfo]:
        prefix = self._fix_path(path) + "/"
        paginator = self._client.get_paginator("list_objects_v2")
        file_list = []

        for page in paginator.paginate(Bucket=self._bucket_name, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith("/"):
                    continue  # skip directory placeholder objects

                file = S3FileInfo(
                    path=f"s3://{self._bucket_name}/{key}",
                    size_gb=obj["Size"] / 1_000**3,
                    uploaded=obj["LastModified"].replace(tzinfo=None),
                )
                self._logger.debug("Found file %s", file)
                file_list.append(file)

        return file_list

    @Decorator.catch_s3_error_and_raise
    def get_file(self, file_path: str, local_directory_path: str) -> str:
        if not os.path.isdir(local_directory_path):
            raise ValueError(f"Local directory path {local_directory_path} does not exist")

        filename = os.path.basename(file_path)
        new_local_file_path = os.path.join(local_directory_path, filename)
        if os.path.isfile(new_local_file_path):
            raise FileExistsError(f"File {new_local_file_path} already exists locally!")

        key = self._fix_path(file_path)
        file_size = self._get_object_size(key)
        callback = ProgressCallback(filename, file_size)

        self._logger.info("Downloading s3://%s/%s → %s", self._bucket_name, key, new_local_file_path)
        self._client.download_file(
            self._bucket_name,
            key,
            new_local_file_path,
            Config=self._transfer_config,
            Callback=callback,
        )
        return new_local_file_path

    @Decorator.catch_s3_error_and_raise
    def upload_file(self, local_file_path: str, destination_directory_path: str) -> str:
        if not os.path.isfile(local_file_path):
            raise ValueError(f"Local file path {local_file_path} does not exist")

        filename = os.path.basename(local_file_path)
        key = f"{self._fix_path(destination_directory_path)}/{filename}"
        file_size = os.path.getsize(local_file_path)
        callback = ProgressCallback(filename, file_size)

        self._logger.info("Uploading %s → s3://%s/%s", local_file_path, self._bucket_name, key)
        self._client.upload_file(
            local_file_path,
            self._bucket_name,
            key,
            Config=self._transfer_config,
            Callback=callback,
        )
        return f"s3://{self._bucket_name}/{key}"

    def _get_object_size(self, key: str) -> int:
        """Return object size in bytes, or 0 if it cannot be determined."""
        try:
            response = self._client.head_object(Bucket=self._bucket_name, Key=key)
            return response.get("ContentLength", 0)
        except ClientError:
            return 0


    @staticmethod
    def _fix_path(path: str) -> str:
        return path.strip("/")
