import os
import sys
from datetime import datetime
from pathlib import Path
from hashlib import file_digest, md5


FILE_LIST = "files.lst"
FILE_EXTENSION = ".tar.enc"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
CELL_DELIMITER = ";"


def main()  -> None:
    if len(sys.argv) < 2:
        print("Usage: python create-files-list.py <directory>")
        return

    files_dir = Path(sys.argv[1])
    if not files_dir.is_dir():
        print(f"{files_dir} is not a valid directory.")
        return

    file_path = Path(FILE_LIST)
    if file_path.exists():
        print(f"{FILE_LIST} already exists. Remove it first if you want to recreate it.")
        return

    file_count = 0
    with open(FILE_LIST, "w") as f_list:
        for file_path in files_dir.rglob(f'*{FILE_EXTENSION}'):
            print(f"Adding file {file_path}...")
            with open(file_path, "rb") as f:
                digest = file_digest(f, md5).hexdigest()
            file_created = datetime.fromtimestamp(os.path.getctime(file_path))
            f_list.write(
                f"{file_path}{CELL_DELIMITER}{file_created.strftime(DATE_FORMAT)}{CELL_DELIMITER}{digest}\n")
            print(f"{file_path} - OK!")
            file_count += 1

    print(f"File list created at {FILE_LIST} with {file_count} files.")


if __name__ == "__main__":
    main()