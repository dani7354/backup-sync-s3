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
file;uploaded;md5
backup.tar.gz;2025-11-01;d41d8cd98f00b204e9800998ecf8427e
```