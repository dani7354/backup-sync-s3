import argparse
import dataclasses
import functools
import os
import subprocess
import tempfile
from datetime import datetime
from typing import ClassVar, Sequence
from hashlib import sha256

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
    hash: str
    created: datetime


@dataclasses.dataclass(frozen=True)
class BackupLocation:
    local_path: str
    remote_path: str


class S3CmdWrapper:
    """ Wrapper for s3cmd command line utility: https://s3tools.org/ """
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
        if not os.path.isfile(backup_directory_list_path):
            raise FileNotFoundError(f"Backup directory list file {backup_directory_list_path} not found!")
        self._backup_directory_list_path = backup_directory_list_path

    def read_file_list(self, remote_directory_path: str, local_directory_path: str) -> list[Backup]:
        backups = []
        self._s3.get_file(REMOTE_FILE_LIST, remote_directory_path)
        with open(os.path.join(local_directory_path, REMOTE_FILE_LIST), "r") as f:
            for line in f.readlines():
                values = line.split(";")
                created = datetime.strptime(values[0], "%Y-%m-%dT%H:%M:%S.%f")
                filename = values[1]
                digest = values[2]
                backups.append(Backup(filename, digest, created))

        return backups

    def add_to_file_list(self, backups: Sequence[Backup], local_directory_path: str, remote_directory_path) -> None:
        file_list_local_path = os.path.join(local_directory_path, REMOTE_FILE_LIST)
        with open(file_list_local_path, "a") as f:
            for backup in backups:
                f.write(f"{backup.filename};{backup.created.isoformat()};{backup.hash}\n")

        self._s3.upload_file(file_list_local_path, remote_directory_path)

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

        fail_count = 0
        with tempfile.TemporaryDirectory(prefix=self._tmp_directory_prefix) as tmp_dir:
            for backup_location in self.get_backup_locations():
                try:
                    self._sync_backups(tmp_dir, backup_location)
                except S3CommandError as e:
                    fail_count += 1
                    print(f"Error syncing backups for location {backup_location.remote_path}: {e}")

        status_message = f"Backup sync completed with {fail_count} errors." \
            if fail_count else "Backup sync completed successfully."
        print(status_message)


    def _is_instance_running(self) -> bool:
        for item in os.listdir(TMP_DIR_PATH):
            if item.startswith(self._tmp_directory_prefix):
                return True
        return False

    def _sync_backups(self, tmp_dir: str, backup_location: BackupLocation) -> None:
        remote_backups = self.read_file_list(backup_location.remote_path, tmp_dir)

        remote_backup_files = set(backup.filename for backup in remote_backups)
        print(f"{len(remote_backup_files)} remote backups found in {backup_location.remote_path}")

        local_backups = set(os.listdir(backup_location.local_path))
        print(f"{len(local_backups)} local backups found in {backup_location.remote_path}")

        backups_to_upload = local_backups - remote_backup_files
        if backups_to_upload:
            print(f"{len(backups_to_upload)} backups will be uploaded to {backup_location.remote_path}")
        else:
            print(f"No new backups to upload to {backup_location.remote_path}")
            return

        backup_upload_status = {}
        for backup_filename in backups_to_upload:
            local_backup_file_path = os.path.join(backup_location.local_path, backup_filename)
            backup_digest = self._get_sha256_hash(local_backup_file_path)
            new_backup = Backup(local_backup_file_path, backup_digest, datetime.now())

            try:
                print(f"Uploading backup file: {local_backup_file_path} to {backup_location.remote_path}")
                self._s3.upload_file(local_backup_file_path, backup_location.remote_path)
                backup_upload_status[new_backup] = True
            except S3CommandError as e:
                backup_upload_status[new_backup] = False
                print(f"Error uploading backup file {backup_filename}: {e}")

        successful_uploads = []
        failed_upload_count = 0
        for backup, success in backup_upload_status.items():
            if success:
                successful_uploads.append(backup)
            else:
                failed_upload_count += 1

        if successful_uploads:
            print("Adding new backups to file list...")
            successful_uploads = [backup for backup, status in backup_upload_status.items() if status]
            self.add_to_file_list(successful_uploads, tmp_dir, backup_location.remote_path)

        if failed_upload_count:
            print(f"{failed_upload_count} backups failed to upload to {backup_location.remote_path}")

    @staticmethod
    def _get_sha256_hash(input_file: str) -> str:
        sha256_hash = sha256()
        with open(input_file, "rb") as f:
            while byte_block := f.read(4096):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


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
