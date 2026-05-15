# backup-sync-s3
![Pylint](https://github.com/dani7354/backup-sync-s3/actions/workflows/10-pylint.yml/badge.svg)
![Docker Image Build and Push](https://github.com/dani7354/backup-sync-s3/actions/workflows/15-build-docker-image.yml/badge.svg)


## Installation

1. Clone the repository: `git clone https://github.com/dani7354/backup-sync-s3.git`
2. Create a `.env` file with the required environment variables (see Configuration section below).
3. Create a backup list file `backups.lst` with the local and remote paths of the backups to be synced (see Configuration section below).
4. Create an environment-specific `docker-compose.live.yml` file with the relevant mounts and paths (defined in `backup.lst`). See `docker-compose.dev.yml` for inspiration.
5. Start the service: `docker compose -f docker-compose.yml -f docker-compose.live.yml up -d`


## Configuration

### Environment variables
The following environment variables needs to be set in the Docker container. 
Either in a docker-compose YAML file or in a .env file made available to the container.

See the documentation for your S3 storage provider for the correct values to use. 
(Linode: https://techdocs.akamai.com/cloud-computing/docs/using-the-aws-sdk-for-python-boto3-with-object-storage#installing-boto3)
```
S3_BUCKET_NAME=my-backup-bucket
S3_ENDPOINT_URL=https://s3-endpoint-url
S3_REGION=s3-region
S3_ACCESS_KEY=your-access-key-here
S3_SECRET_KEY=your-secret-key-here
BACKUP_LIST_PATH=/app/backups.lst
```

### Backup list
The `backups.lst` file contains the different backup paths: \
local path;remote path (in s3 bucket)

```
/data/backups/0;/0
/data/backups/2;/2
```

Make sure that the local paths are mounted to the container and the user that runs the service has read access. If it fails
with a permission error, the permissions will need to be adjusted on the host machine, which can be done by using chmod or
setfacl, e.g. `setfacl -R -dm u:2222:rx /data/backups/0` (assuming the container runs with user id 2222).

### Files list
`files.lst` - placed in each remote directory. 
`files.lst`, which is mounted to the container, should contain lines like the ones below. The helper script `helpers/create_files_list.py` can be used to generate this list.

Format: local path;added datetime;file sha256
```
test_volume/backups/0/testfile_0002.tar.enc;2026-04-16T21:09:41.036838;1172905a4fe58483b2c96955f9e04571f7c68a89f93ce17dedd9b9c33516a886
test_volume/backups/0/testfile_0001.tar.enc;2026-04-16T21:09:40.563839;7623f7bb2efa64dab2f6d26e60778f1006d9b1d4382383e9979a6d6d3882a18c
```