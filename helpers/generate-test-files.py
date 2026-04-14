import os
import sys
from pathlib import Path


FILE_SIZE_MB = 150
CHUNK_SIZE = 1024 * 1024  # 1 MB


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python generate-test-files.py <location_dir> <number_of_files>")
        return

    location_dir = Path(sys.argv[1])
    if not location_dir.exists():
        print(f"{location_dir} does not exist. Creating it...")
        location_dir.mkdir(parents=True)
    elif not location_dir.is_dir():
        print(f"{location_dir} is not a valid directory.")
        return

    try:
        num_files = int(sys.argv[2])
        if num_files < 1:
            raise ValueError
    except ValueError:
        print("number_of_files must be a positive integer.")
        return

    total_size = FILE_SIZE_MB * 1024 * 1024

    for i in range(1, num_files + 1):
        file_path = location_dir / f"testfile_{i:04d}.bin"
        print(f"Generating {file_path} ({FILE_SIZE_MB} MB)...")
        bytes_written = 0
        with open(file_path, "wb") as f:
            while bytes_written < total_size:
                chunk = min(CHUNK_SIZE, total_size - bytes_written)
                f.write(os.urandom(chunk))
                bytes_written += chunk
        print(f"{file_path} - OK!")

    print(f"\nDone. {num_files} file(s) of {FILE_SIZE_MB} MB created in '{location_dir}'.")


if __name__ == "__main__":
    main()

