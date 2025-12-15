# backup-sync-s3


## Installation

1. `$ python3 -m venv venv/ && source venv/bin/activate`
2. `$ pip install -r requirements.txt`
3. `$ s3cmd --configure`. See https://techdocs.akamai.com/cloud-computing/docs/using-s3cmd-with-object-storage


## Configuration
`backups.lst` (given as argument when running the script) should contain lines like this:
```
local_directory;remote_directory
/path/to/local/dir0;/path/to/remote/dir0
/another_path/to/local/dir1;/another_path/to/remote/dir1
```

`files.lst` - placed in each remote directory
```
file;uploaded;sha256
backup.tar.gz;2025-11-01;3ac1fcef9cd7368c9bbf491b27766d670ab3c6507d47396898f046b4ef32009a
```