import dataclasses
import os
import time
import schedule

import tempfile
from dataclasses import field
from datetime import datetime
from logging import getLogger
from typing import ClassVar, Sequence
from pathlib import Path
from hashlib import sha256, file_digest
from threading import Thread, Lock

from backup_sync_s3.s3 import S3Wrapper, S3CommandError
from backup_sync_s3.config import (
    INCOMPLETE_BACKUP_PREFIX,
    TMP_DIR_PATH,
    REMOTE_FILE_LIST,
    DATE_FORMAT,
    CSV_CELL_DELIMITER,
    SYNC_RUN_INTERVAL,
    SyncInterval
)


@dataclasses.dataclass(frozen=True)
class Backup:
    filename: str = field(compare=True)
    hash: str
    created: datetime

    def __hash__(self) -> int:
        return hash(self.filename)  # In the future, we should use the hash instead - see other comments in this module.

    def __eq__(self, other: Backup) -> bool:
        if not isinstance(other, Backup):
            return False

        return self.filename == other.filename


@dataclasses.dataclass(frozen=True)
class BackupLocation:
    local_path: str
    remote_path: str


class S3BackupSync:
    _sleep_time_s: ClassVar[int] = 86400
    _tmp_directory_prefix: ClassVar[str] = "s3-backup-sync"
    _encoding: ClassVar[str] = "utf-8"
    _default_backup_hash: ClassVar[str] = "x"
    _invalid_backup_prefixes: ClassVar[tuple[str, ...]] = (
        ".",
        INCOMPLETE_BACKUP_PREFIX,
        REMOTE_FILE_LIST,
    )

    def __init__(self, s3: S3Wrapper, backup_directory_list_path: Path) -> None:
        self._s3 = s3
        if not os.path.isfile(backup_directory_list_path):
            raise FileNotFoundError(f"Backup directory list file {backup_directory_list_path} not found!")

        self._backup_directory_list_path = backup_directory_list_path
        self._tmp_directory_path = TMP_DIR_PATH
        self._is_sync_running = False
        self._lock = Lock()
        self._logger = getLogger(self.__class__.__name__)

    def run(self) -> None:
        self._run_backup_sync()
        self._set_up_scheduled_sync()

        while True:
            try:
                schedule.run_pending()
                time.sleep(1)
            except KeyboardInterrupt:
                self._logger.info("Stopping...")
                break

    def _set_up_scheduled_sync(self) -> None:
        def run_threaded(func):
            thread = Thread(target=func)
            thread.start()

        match SYNC_RUN_INTERVAL:
            case SyncInterval.HOURLY:
                schedule.every().hour.do(run_threaded, self._run_backup_sync)
            case SyncInterval.DAILY:
                schedule.every().day.do(run_threaded, self._run_backup_sync)
            case SyncInterval.WEEKLY:
                schedule.every().week.do(run_threaded, self._run_backup_sync)

        self._logger.info("Backup sync will run %s.", SYNC_RUN_INTERVAL.name)

    def _run_backup_sync(self) -> None:
        if not self._set_sync_running(is_running=True):
            self._logger.warning("Backup sync is already running. Skipping...")
            return

        fail_count = 0
        for backup_location in self._get_backup_locations():
            try:
                with tempfile.TemporaryDirectory(prefix=self._tmp_directory_prefix) as tmp_dir:
                    self._sync_backups(tmp_dir, backup_location)
            except S3CommandError as e:
                fail_count += 1
                self._logger.error(
                    "Error syncing backups for location %s: %s",
                    backup_location.remote_path,
                    e,
                )
                self._logger.exception(e)

        if fail_count:
            self._logger.warning("Backup sync completed with %d error(s).", fail_count)
        else:
            self._logger.info("Backup sync completed successfully.")

        self._set_sync_running(is_running=False)

    def _sync_backups(self, tmp_dir: str, backup_location: BackupLocation) -> None:
        if backups_to_upload := self._get_backups_to_upload(backup_location, tmp_dir):
            self._logger.info(
                "%d backup(s) will be uploaded to %s",
                len(backups_to_upload),
                backup_location.remote_path,
            )
        else:
            self._logger.info("No new backups to upload to %s", backup_location.remote_path)
            return

        successful_uploads = []
        failed_upload_count = 0
        for backup, success in self._upload_backups(backup_location, backups_to_upload).items():
            if success:
                successful_uploads.append(backup)
            else:
                failed_upload_count += 1

        if successful_uploads:
            self._logger.info("Adding new backups to file list...")
            self._add_to_file_list(successful_uploads, tmp_dir, backup_location.remote_path)

        if failed_upload_count:
            self._logger.warning(
                "%d backup(s) failed to upload to %s",
                failed_upload_count,
                backup_location.remote_path,
            )

    def _read_file_list_backups(self, remote_directory_path: str, tmp_directory_path: str) -> list[Backup]:
        backups = []
        if not self._s3.list_files(remote_directory_path):
            self._logger.warning("No files in remote dir %s", remote_directory_path)
            return backups

        self._s3.get_file(os.path.join(remote_directory_path, REMOTE_FILE_LIST), tmp_directory_path)
        with open(
            os.path.join(tmp_directory_path, REMOTE_FILE_LIST),
            "r",
            encoding=self._encoding,
        ) as f:
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
            file_path = os.path.join(local_directory_path, file)
            if file.startswith(self._invalid_backup_prefixes) or not os.path.isfile(file_path):
                continue

            file_hash = self._default_backup_hash  # Should be self._get_file_hash(file_path), but now it takes too long
            created_time = datetime.fromtimestamp(os.path.getctime(file_path))
            backups.append(Backup(file_path, file_hash, created_time))

        return backups

    def _add_to_file_list(
        self,
        backups: Sequence[Backup],
        local_directory_path: str,
        remote_directory_path: str,
    ) -> None:
        file_list_local_path = os.path.join(local_directory_path, REMOTE_FILE_LIST)
        with open(file_list_local_path, "a", encoding=self._encoding) as f:
            for backup in backups:
                self._logger.debug("Adding to file list: %s", backup)
                f.write(f"{backup.filename};{backup.created.strftime(DATE_FORMAT)};{backup.hash}\n")

        self._s3.upload_file(file_list_local_path, remote_directory_path)

    def _get_backup_locations(self) -> list[BackupLocation]:
        backup_locations = []
        with open(self._backup_directory_list_path, "r", encoding=self._encoding) as f:
            for line in f.readlines():
                local_path, remote_path = line.split(CSV_CELL_DELIMITER)
                self._logger.info(
                    "Found backup location - local: %s, remote: %s",
                    local_path.strip(),
                    remote_path.strip(),
                )
                backup_locations.append(BackupLocation(local_path.strip(), remote_path.strip()))

        return backup_locations

    def _get_backups_to_upload(self, backup_location: BackupLocation, tmp_directory: str) -> list[Backup]:
        remote_backups = set(self._read_file_list_backups(backup_location.remote_path, tmp_directory))
        self._logger.info(
            "%d remote backup(s) found in %s",
            len(remote_backups),
            backup_location.remote_path,
        )

        local_backups = set(self._get_local_backups(backup_location.local_path))
        self._logger.info(
            "%d local backup(s) found in %s",
            len(local_backups),
            backup_location.local_path,
        )

        # make diff on name instead of hash because of performance issues.
        remote_backup_names = set(x.filename for x in remote_backups)

        return list(x for x in local_backups if x.filename not in remote_backup_names)

    def _upload_backups(self, backup_location: BackupLocation, backups: Sequence[Backup]) -> dict[Backup, bool]:
        backup_upload_status: dict[Backup, bool] = {}
        for backup in backups:
            local_backup_file_path = os.path.join(backup_location.local_path, backup.filename)
            new_backup = Backup(local_backup_file_path, backup.hash, datetime.now())

            try:
                self._logger.info(
                    "Uploading backup file: %s to %s",
                    local_backup_file_path,
                    backup_location.remote_path,
                )
                self._s3.upload_file(local_backup_file_path, backup_location.remote_path)
                backup_upload_status[new_backup] = True
            except S3CommandError as e:
                backup_upload_status[new_backup] = False
                self._logger.error("Error uploading backup file %s: %s", backup.filename, e)
                self._logger.exception(e)

        return backup_upload_status

    def _set_sync_running(self, is_running: bool) -> bool:
        with self._lock:
            if is_running and self._is_sync_running:
                return False

            self._is_sync_running = is_running
            return True

    @classmethod
    def _get_file_hash(cls, input_file: str) -> str:
        with open(input_file, "rb") as f:
            return file_digest(f, sha256).hexdigest()
