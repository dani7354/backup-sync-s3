import argparse
import dataclasses
import functools
import os
import subprocess
import tempfile
from argparse import ArgumentParser
from collections.abc import Sequence
from datetime import datetime
from typing import ClassVar, Iterable

REMOTE_FILE_LIST = "files.lst"
TMP_DIR_PATH = "/tmp"
ENCODING = "utf-8"


class S3CommandError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class S3FileInfo:
    path: str
    size_gb: int
    uploaded: datetime


@dataclasses.dataclass(frozen=True)
class Backup:
    filename: str
    created: datetime


@dataclasses.dataclass(frozen=True)
class BackupLocation:
    local_path: str
    remote_path: str


class S3CmdWrapper:
    """ Wrapper for s3cmd command line utility: https://s3tools.org/"""
    config_filename: ClassVar[str] = ".s3cfg"
    s3cmd: ClassVar[str] = "s3cmd"

    def __init__(self, bucket_name: str) -> None:
        self._bucket_url = f"s3://{bucket_name}"
        self._tmp_directory_path = TMP_DIR_PATH
        self._s3_cmd = self._get_s3cmd_path()
        if not self._check_s3cmd_cfg_exists():
            raise FileNotFoundError("s3cmd configuration file not found. You need to run s3cmd --configure first!")


    class Decorator:
        @classmethod
        def catch_process_error_and_raise(cls, func):
            @functools.wraps(func)
            def inner(self, *args, **kwargs):
                try:
                    return func(self, *args, **kwargs)
                except subprocess.CalledProcessError as e:
                    print(f"Command failed! {e}")
                    raise S3CommandError from e

            return inner

    @Decorator.catch_process_error_and_raise
    def list_files(self, path: str) -> list[S3FileInfo]:
        cmd = [self._s3_cmd, "ls", f"{self._bucket_url}/{self._fix_path(path)}/"]
        cmd_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        cmd_output_str = cmd_output.decode(ENCODING)
        file_list = []
        for line in cmd_output_str.splitlines():
            line_split = line.split()
            if len(line_split) < 4:
                continue

            file_list.append(
                S3FileInfo(
                    path=line_split[-1],
                    size_gb=int(line_split[2]) / 1000**3,
                    uploaded=datetime.strptime(f"{line_split[0]} {line_split[1]}", "%Y-%m-%d %H:%M")))

        return file_list

    @Decorator.catch_process_error_and_raise
    def get_file(self, file_path: str, local_directory_path: str) -> str:
        if not os.path.isdir(local_directory_path):
            raise ValueError(f"Local directory path {local_directory_path} does not exist")

        new_local_file_path = os.path.join(local_directory_path, os.path.split(file_path)[-1])
        if os.path.isfile(new_local_file_path):
            raise FileExistsError(f"File {new_local_file_path} already exists locally!")

        cmd = [self._s3_cmd, "--progress", "get", f"{self._bucket_url}/{self._fix_path(file_path)}", local_directory_path]
        _ = subprocess.check_output(cmd, stderr=subprocess.STDOUT)

        return new_local_file_path

    @Decorator.catch_process_error_and_raise
    def upload_file(self, local_file_path: str, destination_directory_path: str) -> str:
        if not os.path.isfile(local_file_path):
            raise ValueError(f"Local file path {local_file_path} does not exist")

        new_file_remote_path  = (
            f"{self._bucket_url}/{self._fix_path(destination_directory_path)}/{os.path.split(local_file_path)[-1]}")
        cmd = [self._s3_cmd, "--progress", "put", local_file_path, new_file_remote_path]
        _ = subprocess.check_output(cmd, stderr=subprocess.STDOUT)

        return new_file_remote_path

    @staticmethod
    def _get_s3cmd_path() -> str:
        cmd_output = subprocess.check_output(["which", "s3cmd"])
        return cmd_output.decode(ENCODING).strip()

    @staticmethod
    def _check_s3cmd_cfg_exists() -> bool:
        home_dir = os.path.expanduser("~")
        s3cfg_path = os.path.join(home_dir, ".s3cfg")
        return os.path.isfile(s3cfg_path)

    @staticmethod
    def _fix_path(path: str) -> str:
        return path.lstrip("/").rstrip("/")


class S3BackupSync:
    _tmp_directory_prefix: ClassVar[str] = "s3-backup-sync"

    def __init__(self, s3: S3CmdWrapper, backup_directory_list_path: str) -> None:
        self._s3 = s3
        self._backup_directory_list_path = backup_directory_list_path

    def read_file_list(self, remote_directory_path: str, local_directory_path: str) -> list[Backup]:
        backups = []
        self._s3.get_file(REMOTE_FILE_LIST, local_directory_path)
        with open(os.path.join(local_directory_path, REMOTE_FILE_LIST), "r") as f:
            for line in f.readlines():
                values = line.split(";")
                created = datetime.strptime(values[0], "%Y-%m-%dT%H:%M:%S.%f")
                filename = values[1]
                backups.append(Backup(filename, created))
        return backups

    def get_backup_locations(self) -> list[BackupLocation]:
        backup_locations = []
        with open(self._backup_directory_list_path, mode="r") as f:
            for l in f.readlines():
                local_path, remote_path = l.split(";")
                backup_locations.append(BackupLocation(local_path, remote_path))

        return backup_locations


    def run_backup_sync(self) -> None:
        if self._is_instance_running():
            print(f"An instance of {self.__class__.__name__} is already running! Closing...")
            return

        with tempfile.TemporaryDirectory(prefix=self._tmp_directory_prefix) as tmp_dir:
            for backup_location in self.get_backup_locations():
                backups = self.read_file_list(backup_location.remote_path, tmp_dir)


    def _is_instance_running(self) -> bool:
        for item in os.listdir(TMP_DIR_PATH):
            if item.startswith(self._tmp_directory_prefix):
                return True
        return False


def parse_arguments():
    parser = argparse.ArgumentParser(prog="s3_backup_sync.py", description="S3 Backup Sync")
    parser.add_argument(
        "-l",
        "--directory-list-path",
        help="Text file containing location of encrypted backups",
        dest="directory_list_path",
        type=str,
        nargs=1,
        required=True
    )
    return parser.parse_args


def main():
    args = parse_arguments()
    bucket_name = os.environ["S3_BUCKET_NAME"]
    s3 = S3CmdWrapper(bucket_name)

    file_list = s3.list_files("backup/e14")
    print(file_list)

    #downloaded_file = s3.get_file("/backup/e14/files_1.lst", ".")
    #print(downloaded_file)

    new_uploaded_file = s3.upload_file("./files_1.lst", "backup/e14")
    print(new_uploaded_file)
    #s3_backup_sync = S3BackupSync(s3, args.directory_list_path)


if __name__ == "__main__":
    main()
