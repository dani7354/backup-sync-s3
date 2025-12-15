import argparse
import dataclasses
import functools
import os
import subprocess
import tempfile
import pathlib
from dataclasses import field
from datetime import datetime
from typing import ClassVar, Sequence
from hashlib import sha256


S3_BUCKET_NAME_ENV_VAR = "S3_BUCKET_NAME"

REMOTE_FILE_LIST = "files.lst"
CSV_CELL_DELIMITER = ";"

TMP_DIR_PATH = "/tmp"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
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
    hash: str = field(compare=True)
    created: datetime

    def __hash__(self) -> int:
        return hash(self.hash)

    def __eq__(self, other) -> bool:
        if not isinstance(other, Backup):
            return False
        return self.hash == other.hash


@dataclasses.dataclass(frozen=True)
class BackupLocation:
    local_path: str
    remote_path: str


class S3CmdWrapper:
    """ Wrapper for s3cmd command line utility: https://s3tools.org/ """
    config_filename: ClassVar[str] = ".s3cfg"

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
        return path.strip("/")


class S3BackupSync:
    _tmp_directory_prefix: ClassVar[str] = "s3-backup-sync"

    def __init__(self, s3: S3CmdWrapper, backup_directory_list_path: pathlib.Path) -> None:
        self._s3 = s3
        if not os.path.isfile(backup_directory_list_path):
            raise FileNotFoundError(f"Backup directory list file {backup_directory_list_path} not found!")
        self._backup_directory_list_path = backup_directory_list_path
        self._tmp_directory_path = TMP_DIR_PATH

    def run_backup_sync(self) -> None:
        if self._is_instance_running():
            print(f"An instance of {self.__class__.__name__} is already running! Closing...")
            return

        fail_count = 0
        with tempfile.TemporaryDirectory(prefix=self._tmp_directory_prefix) as tmp_dir:
            for backup_location in self._get_backup_locations():
                try:
                    self._sync_backups(tmp_dir, backup_location)
                except S3CommandError as e:
                    fail_count += 1
                    print(f"Error syncing backups for location {backup_location.remote_path}: {e}")

        status_message = f"Backup sync completed with {fail_count} errors." \
            if fail_count else "Backup sync completed successfully."
        print(status_message)

    def _sync_backups(self, tmp_dir: str, backup_location: BackupLocation) -> None:
        if backups_to_upload := self._get_backups_to_upload(backup_location, tmp_dir):
            print(f"{len(backups_to_upload)} backups will be uploaded to {backup_location.remote_path}")
        else:
            print(f"No new backups to upload to {backup_location.remote_path}")
            return

        successful_uploads = []
        failed_upload_count = 0
        for backup, success in self._upload_backups(backup_location, backups_to_upload).items():
            if success:
                successful_uploads.append(backup)
            else:
                failed_upload_count += 1

        if successful_uploads:
            print("Adding new backups to file list...")
            self._add_to_file_list(successful_uploads, tmp_dir, backup_location.remote_path)

        if failed_upload_count:
            print(f"{failed_upload_count} backups failed to upload to {backup_location.remote_path}")

    def _read_file_list_backups(self, remote_directory_path: str, tmp_directory_path: str) -> list[Backup]:
        backups = []
        self._s3.get_file(os.path.join(remote_directory_path, REMOTE_FILE_LIST), tmp_directory_path)
        with open(os.path.join(tmp_directory_path, REMOTE_FILE_LIST), "r") as f:
            for line in f.readlines():
                values = line.rstrip().split(CSV_CELL_DELIMITER)
                filename = values[0]
                created = datetime.strptime(values[1], DATE_FORMAT)
                digest = values[2]
                backups.append(Backup(filename, digest, created))

        return backups

    def _get_local_backups(self, local_directory_path: str) -> list[Backup]:
        backups = []
        for file in os.listdir(local_directory_path):
            if file.startswith(".") or not os.path.isfile(file):
                continue

            file_path = os.path.join(local_directory_path, file)
            file_hash = self._get_sha256_hash(file_path)
            created_time = datetime.fromtimestamp(os.path.getctime(file_path))
            backups.append(Backup(file, file_hash, created_time))

        return backups

    def _add_to_file_list(self, backups: Sequence[Backup], local_directory_path: str, remote_directory_path) -> None:
        file_list_local_path = os.path.join(local_directory_path, REMOTE_FILE_LIST)
        with open(file_list_local_path, "a") as f:
            for backup in backups:
                print("adding to file list:", backup)
                f.write(f"{backup.filename};{backup.created.strftime(DATE_FORMAT)};{backup.hash}\n")

        self._s3.upload_file(file_list_local_path, remote_directory_path)

    def _get_backup_locations(self) -> list[BackupLocation]:
        backup_locations = []
        with open(self._backup_directory_list_path, mode="r") as f:
            for line in f.readlines():
                local_path, remote_path = line.split(CSV_CELL_DELIMITER)
                print(f"Found backup location - local: {local_path}, remote: {remote_path}")
                backup_locations.append(BackupLocation(local_path, remote_path))

        return backup_locations

    def _get_backups_to_upload(self, backup_location: BackupLocation, tmp_directory: str) -> list[Backup]:
        remote_backups = set(self._read_file_list_backups(backup_location.remote_path, tmp_directory))
        print(f"{len(remote_backups)} remote backups found in {backup_location.remote_path}")

        local_backups = set(self._get_local_backups(backup_location.local_path))
        print(f"{len(local_backups)} local backups found in {backup_location.remote_path}")

        return list(local_backups - remote_backups)

    def _upload_backups(self, backup_location: BackupLocation, backups: Sequence[Backup]) -> dict[Backup, bool]:
        backup_upload_status = {}
        for backup in backups:
            local_backup_file_path = os.path.join(backup_location.local_path, backup.filename)
            backup_digest = self._get_sha256_hash(local_backup_file_path)
            new_backup = Backup(local_backup_file_path, backup_digest, datetime.now())

            try:
                print(f"Uploading backup file: {local_backup_file_path} to {backup_location.remote_path}")
                self._s3.upload_file(local_backup_file_path, backup_location.remote_path)
                backup_upload_status[new_backup] = True
            except S3CommandError as e:
                backup_upload_status[new_backup] = False
                print(f"Error uploading backup file {backup.filename}: {e}")

        return backup_upload_status

    def _is_instance_running(self) -> bool:
        for item in os.listdir(self._tmp_directory_path):
            if item.startswith(self._tmp_directory_prefix):
                return True
        return False

    @staticmethod
    def _get_sha256_hash(input_file: str) -> str:
        sha256_hash = sha256()
        with open(input_file, "rb") as f:
            while byte_block := f.read(4096):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def _parse_arguments():
    parser = argparse.ArgumentParser(prog="s3_backup_sync.py", description="S3 Backup Sync")
    parser.add_argument(
        "-l",
        "--backup-list-path",
        help="TXT file containing location of encrypted backups",
        dest="backup_list_path",
        type=pathlib.Path,
        required=True)
    return parser.parse_args()


def _validate_and_get_backup_list(args: argparse.Namespace) -> pathlib.Path:
    if not (backups_path := args.backup_list_path) or not backups_path.is_file():
        raise FileNotFoundError(f"Backup directory list file {backups_path} not found!")

    return backups_path


def _validate_and_get_s3_bucket_name() -> str:
    if not (s3_bucket_name := os.environ.get(S3_BUCKET_NAME_ENV_VAR)):
        raise EnvironmentError(f"{S3_BUCKET_NAME_ENV_VAR} environment variable not set!")
    if len(s3_bucket_name) < 3:
        raise ValueError(f"S3 bucket name {s3_bucket_name} is invalid")

    return s3_bucket_name


def main() -> None:
    args = _parse_arguments()
    backup_directory_list_path = _validate_and_get_backup_list(args)
    s3_bucket_name = _validate_and_get_s3_bucket_name()

    s3 = S3CmdWrapper(s3_bucket_name)
    s3_backup_sync = S3BackupSync(s3, backup_directory_list_path)
    s3_backup_sync.run_backup_sync()


if __name__ == "__main__":
    main()
