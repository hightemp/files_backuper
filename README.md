# files_backuper

Files Backuper is a application designed to automate the process of backing up and synchronizing files from multiple servers. With specific configurations, it facilitates seamless backup creation, storage management, and restoration processes via SFTP and SSH.

## Features

- **Automated Backups**: Schedule backups according to a specified time interval.
- **Flexible Configuration**: Easily configure servers and paths to back up through YAML files.
- **Multi-Server Support**: Handle backups from multiple servers with ease.
- **Change Detection**: Automatically detect changes in files and create incremental backups.
- **Restoration**: Simple and efficient restoration process using the latest backups.

## Installation

Clone the repository and build the application using Go:

```bash
git clone https://github.com/hightemp/files_backuper.git
cd files_backuper
go build -o files_backuper
```

## Configuration

The application uses a YAML configuration file defining servers, settings, and backup configurations. Below is an example configuration:

```yaml
# Config.yaml
Servers:
  - Name: example-server
    Type: ssh
    Host: your.server.com
    Port: 22
    User: your_user
    Password: your_password # If using password authentication
    IdentityFile: /path/to/private/key # If using key-based authentication

Settings:
  BackupSaveFolder: /path/to/local/backup/folder
  CheckChangesTimeout: 10m
  MaxBackupsCount: 5
  BackupsDatabase: /path/to/database.yaml

BackupsConfigs:
  - Name: daily-backup
    Server: example-server
    Path: /remote/path/to/backup
```

## Usage

Run the application with the desired flags:

```bash
./files_backuper -config ./config.yaml -run_as_service
```

### Flags

- `-config` : Path to the YAML configuration file.
- `-run_as_service` : Run the application as a service, continuously checking and creating backups.
- `-backup_server` : Force a backup for a specific server by name.
- `-backup` : Force a specific backup by name.
- `-upload_latest_backup` : Upload the latest backup for a specified backup configuration.
- `-upload_latest_server_backup` : Upload the latest backup for a specified server by name.

## License

MIT License

[![](https://asdertasd.site/counter/files_backuper?a=1)](https://asdertasd.site/counter/files_backuper)