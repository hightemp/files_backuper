package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Server struct {
	Name         string `yaml:"Name"`
	Type         string `yaml:"Type"`
	Host         string `yaml:"Host"`
	Port         int    `yaml:"Port"`
	User         string `yaml:"User"`
	Password     string `yaml:"Password,omitempty"`
	IdentityFile string `yaml:"IdentityFile,omitempty"`
}

type Settings struct {
	BackupSaveFolder    string `yaml:"BackupSaveFolder"`
	CheckChangesTimeout string `yaml:"CheckChangesTimeout"`
	MaxBackupsCount     int    `yaml:"MaxBackupsCount"`
	BackupsDatabase     string `yaml:"BackupsDatabase"`
}

type BackupConfig struct {
	Name   string `yaml:"Name"`
	Server string `yaml:"Server"`
	Path   string `yaml:"Path"`
}

type Config struct {
	Servers        []Server       `yaml:"Servers"`
	Settings       Settings       `yaml:"Settings"`
	BackupsConfigs []BackupConfig `yaml:"BackupConfig"`
}

type BackupedFile struct {
	Path         string `yaml:"Path"`
	RelativePath string `yaml:"RelativePath"`
	Hash         string `yaml:"Hash"`
}

type Backup struct {
	Name             string         `yaml:"Name"`
	BackupConfigName string         `yaml:"BackupConfigName"`
	BackupServerName string         `yaml:"BackupServerName"`
	Path             string         `yaml:"Path"`
	CreatedAt        time.Time      `yaml:"CreatedAt"`
	Hash             string         `yaml:"Hash"`
	Files            []BackupedFile `yaml:"Files"`
}

type Database struct {
	Backups []Backup `yaml:"Backups"`
}

var (
	config                      Config
	database                    Database
	argConfigPath               *string
	argBackupServerName         *string
	argBackupName               *string
	argUploadLatestBackup       *string
	argUploadLatestServerBackup *string
	runAsService                *bool
	currentBackup               *Backup
	checkChangesTimeout         time.Duration
)

func LoadConfig(path string) error {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Error reading YAML file: %v", err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return fmt.Errorf("Error parsing YAML file: %v", err)
	}

	log.Printf("Parsed YAML config: %#v\n", config)

	checkChangesTimeout, err = parseDuration(config.Settings.CheckChangesTimeout)
	if err != nil {
		return fmt.Errorf("Error parsing CheckChangesTimeout: %v", err)
	}

	return nil
}

func WriteDatabaseFile() error {
	path := config.Settings.BackupsDatabase
	yml, err := yaml.Marshal(database)
	if err != nil {
		return fmt.Errorf("Error preparing YAML file: %v", err)
	}

	err = os.WriteFile(path, yml, 0644)
	if err != nil {
		return fmt.Errorf("Error writing YAML file: %v", err)
	}

	return nil
}

func LoadBackupsDatabase() error {
	path := config.Settings.BackupsDatabase
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err2 := WriteDatabaseFile()
		if err2 != nil {
			return fmt.Errorf("Error writing database: %w", err2)
		}
	}

	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Error reading YAML file: %w", err)
	}

	err = yaml.Unmarshal(yamlFile, &database)
	if err != nil {
		return fmt.Errorf("Error parsing YAML file: %w", err)
	}

	log.Printf("Parsed YAML database: %#v\n", database)

	return nil
}

func CalculateHashOfBackup(backup *Backup) (string, error) {
	var sumhash string
	for _, backupFile := range backup.Files {
		filehash, err := CalculateHashOfString(backupFile.Hash)
		if err != nil {
			return "", fmt.Errorf("Error calculating hash of backup file: %w", err)
		}
		sumhash = sumhash + filehash
	}
	sumhash, err := CalculateHashOfString(sumhash)
	if err != nil {
		return "", fmt.Errorf("Error calculating hash of backup file: %w", err)
	}
	return sumhash, nil
}

func CalculateHashOfString(str string) (string, error) {
	h := sha256.New()
	_, err := io.WriteString(h, str)
	if err != nil {
		return "", fmt.Errorf("Error calculating hash of String: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func CalculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashBytes := hash.Sum(nil)
	hashStr := hex.EncodeToString(hashBytes)
	return hashStr, nil
}

func FindServerByName(name string) (*Server, error) {
	for i := 0; i < len(config.Servers); i++ {
		if name == config.Servers[i].Name {
			return &config.Servers[i], nil
		}
	}
	return nil, fmt.Errorf("Server '%s' not found", name)
}

func FindBackupConfigByName(name string) (*BackupConfig, error) {
	for i := 0; i < len(config.BackupsConfigs); i++ {
		if name == config.BackupsConfigs[i].Name {
			return &config.BackupsConfigs[i], nil
		}
	}
	return nil, fmt.Errorf("Backup config '%s' not found", name)
}

func FindBackupConfigsWithServerName(name string) []*BackupConfig {
	var backups []*BackupConfig = make([]*BackupConfig, 0, 100)
	for i := 0; i < len(config.BackupsConfigs); i++ {
		if name == config.BackupsConfigs[i].Server {
			backups = append(backups, &config.BackupsConfigs[i])
		}
	}
	return backups
}

func loadPrivateKey(filePath string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}

func CreateBackupFolderForServer(server *Server, backupConfig *BackupConfig) (string, string, error) {
	currentTime := time.Now()
	timeString := currentTime.Format("2006-01-02_15-04-05")
	path := fmt.Sprintf("%s/%s/%s/%s", config.Settings.BackupSaveFolder, server.Name, backupConfig.Name, timeString)
	err := os.MkdirAll(path, 0777)
	if err != nil {
		return "", "", fmt.Errorf("Error creating backup folder for server '%s': %w", server.Name, err)
	}
	return path, timeString, nil
}

func parseDuration(input string) (time.Duration, error) {
	if len(input) < 2 {
		return 0, fmt.Errorf("Invalid input")
	}

	unit := input[len(input)-1]
	value, err := strconv.Atoi(input[:len(input)-1])
	if err != nil {
		return 0, err
	}

	switch unit {
	case 's':
		return time.Duration(value) * time.Second, nil
	case 'm':
		return time.Duration(value) * time.Minute, nil
	case 'h':
		return time.Duration(value) * time.Hour, nil
	default:
		return 0, fmt.Errorf("Invalid unit")
	}
}

func getLatestBackupsByServerName(serverName string) ([]*Backup, error) {
	server, err := FindServerByName(serverName)
	if err != nil {
		return nil, fmt.Errorf("Error finding server '%s': %w", serverName, err)
	}

	return getLatestBackupsForServer(server)
}

func getLatestBackupsForServer(server *Server) ([]*Backup, error) {
	backupConfigs := FindBackupConfigsWithServerName(server.Name)

	backups := make([]*Backup, 0, len(backupConfigs))
	for i := 0; i < len(backupConfigs); i++ {
		backup := getLatestBackup(backupConfigs[i].Name)
		backups = append(backups, backup)
	}

	return backups, nil
}

func getLatestBackup(backupConfigName string) *Backup {
	var latestBackup *Backup = nil
	for _, backup := range database.Backups {
		if backup.BackupConfigName == backupConfigName {
			if latestBackup != nil {
				if backup.CreatedAt.Compare(latestBackup.CreatedAt) == 1 {
					latestBackup = &backup
				}
			} else {
				latestBackup = &backup
			}
		}
	}
	return latestBackup
}

func removeBackup(backupName string) error {
	log.Printf("Removing backup: %s", backupName)

	// Найдем и удалим бэкап из базы данных
	for i, backup := range database.Backups {
		if backup.Name == backupName {
			// Удаление файлов на диске
			err := os.RemoveAll(backup.Path)
			if err != nil {
				return fmt.Errorf("Error removing backup files from disk: %w", err)
			}

			// Удаление из базы данных
			database.Backups = append(database.Backups[:i], database.Backups[i+1:]...)
			if err := WriteDatabaseFile(); err != nil {
				return fmt.Errorf("Error writing updated database file: %w", err)
			}

			log.Printf("Backup %s removed successfully", backupName)
			return nil
		}
	}

	return fmt.Errorf("Backup '%s' not found", backupName)
}

func removeUnnecessaryOldOnes(backupConfig *BackupConfig) error {
	log.Printf("Removing old backups: %s", backupConfig.Name)

	var backups []Backup
	for _, backup := range database.Backups {
		if backup.BackupConfigName == backupConfig.Name {
			backups = append(backups, backup)
		}
	}

	// Если количество бэкапов не превышает MaxBackupsCount, ничего не делаем
	if len(backups) <= config.Settings.MaxBackupsCount {
		return nil
	}

	// Удаляем старые бэкапы, чтобы их количество не превышало MaxBackupsCount
	for len(backups) > config.Settings.MaxBackupsCount {
		// Сортируем бэкапы по дате создания, от более старых к более новым
		sort.SliceStable(backups, func(i, j int) bool {
			return backups[i].CreatedAt.Before(backups[j].CreatedAt)
		})

		oldBackup := backups[0]
		if err := removeBackup(oldBackup.Name); err != nil {
			return fmt.Errorf("Error removing backup '%s': %w", oldBackup.Name, err)
		}
		backups = backups[1:]
	}

	return nil
}

func makeBackup(backupConfigName string) error {
	log.Printf("Starting backup for config '%s'\n", backupConfigName)

	backupConfig, err := FindBackupConfigByName(backupConfigName)

	if err != nil {
		return fmt.Errorf("Can't find backup config: %w", err)
	}

	server, err := FindServerByName(backupConfig.Server)
	if err != nil {
		return fmt.Errorf("Can't find server: %w", err)
	}

	var sshConfig *ssh.ClientConfig = nil

	if server.Password != "" {
		sshConfig = &ssh.ClientConfig{
			User: server.User,
			Auth: []ssh.AuthMethod{
				ssh.Password(server.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else if server.IdentityFile != "" {
		authMethod, err2 := loadPrivateKey(server.IdentityFile)
		if err2 != nil {
			return fmt.Errorf("Failed to load private key: %w", err)
		}

		sshConfig = &ssh.ClientConfig{
			User: server.User,
			Auth: []ssh.AuthMethod{
				authMethod,
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else {
		return fmt.Errorf("Can't find password or identity file")
	}

	addr := fmt.Sprintf("%s:%d", server.Host, server.Port)
	sshConn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("Failed to dial SSH: %w", err)
	}
	log.Printf("Connected to server: %s", addr)
	defer sshConn.Close()

	client, err := sftp.NewClient(sshConn)
	if err != nil {
		return fmt.Errorf("Failed to create SFTP client: %w", err)
	}
	defer client.Close()

	localBackupPath, dirWithDate, err := CreateBackupFolderForServer(server, backupConfig)

	// backupName := backupConfigName+"_"+dirWithDate

	currentBackup = &Backup{
		Name:             dirWithDate,
		CreatedAt:        time.Now(),
		Files:            []BackupedFile{},
		BackupConfigName: backupConfigName,
		BackupServerName: backupConfig.Server,
		Path:             localBackupPath,
		Hash:             "",
	}

	err = copyDirectory(client, backupConfig.Path, localBackupPath)
	if err != nil {
		return fmt.Errorf("Failed to copy directory: %w", err)
	}

	backupHash, err := CalculateHashOfBackup(currentBackup)
	if err != nil {
		return fmt.Errorf("Failed to calculate backup hash: %w", err)
	}
	currentBackup.Hash = backupHash

	database.Backups = append(database.Backups, *currentBackup)

	err = removeUnnecessaryOldOnes(backupConfig)
	if err != nil {
		return fmt.Errorf("Error removing old backups: %w", err)
	}

	err = WriteDatabaseFile()
	if err != nil {
		return fmt.Errorf("Error writing file: %w", err)
	}

	return nil
}

func addFileToDatabase(filePath string) error {
	hash, err := CalculateFileHash(filePath)
	if err != nil {
		return fmt.Errorf("Error calculating file hash: %w", err)
	}

	relativePath := strings.ReplaceAll(filePath, currentBackup.Path+"/", "")

	file := BackupedFile{
		Path:         filePath,
		Hash:         hash,
		RelativePath: relativePath,
	}
	currentBackup.Files = append(currentBackup.Files, file)

	return nil
}

func makeServerBackup(name string) error {
	server, err := FindServerByName(name)

	if err != nil {
		return fmt.Errorf("Can't find server: %w", err)
	}

	log.Printf("Found server: %s", server.Name)

	backupsConfigs := FindBackupConfigsWithServerName(name)

	log.Printf("Found %d backups configs", len(backupsConfigs))

	for _, backupConfig := range backupsConfigs {
		err = makeBackup(backupConfig.Name)
		if err != nil {
			return fmt.Errorf("Can't create backup: %w", err)
		}
	}

	return nil
}

func copyDirectory(client *sftp.Client, remoteDir, localDir string) error {
	remoteFiles, err := client.ReadDir(remoteDir)
	if err != nil {
		return err
	}

	if err = os.MkdirAll(localDir, os.ModePerm); err != nil {
		return err
	}
	log.Printf("Copied directory: %s", localDir)

	for _, file := range remoteFiles {
		remotePath := filepath.Join(remoteDir, file.Name())
		localPath := filepath.Join(localDir, file.Name())

		if file.IsDir() {
			if err = copyDirectory(client, remotePath, localPath); err != nil {
				return err
			}
		} else {
			if err = copyFile(client, remotePath, localPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func copyFile(client *sftp.Client, remoteFile, localFile string) error {
	srcFile, err := client.Open(remoteFile)
	if err != nil {
		return fmt.Errorf("Can't open source file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("Error creating file: %w", err)
	}
	defer dstFile.Close()

	if _, err = io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("Error copying file: %w", err)
	}
	log.Printf("Copied file: %s", localFile)

	err = addFileToDatabase(localFile)
	if err != nil {
		return fmt.Errorf("Error adding file to database: %w", err)
	}

	return nil
}

func uploadLatestServerBackup(serverName string) error {
	backupConfigs := FindBackupConfigsWithServerName(serverName)

	for _, backupConfig := range backupConfigs {
		err := uploadLatestBackup(backupConfig.Name)
		if err != nil {
			return fmt.Errorf("Error uploading latest backup: %w", err)
		}
	}

	return nil
}

func uploadLatestBackup(backupConfigName string) error {
	latestBackup := getLatestBackup(backupConfigName)

	backupConfig, err := FindBackupConfigByName(backupConfigName)
	if err != nil {
		return fmt.Errorf("Can't find backup config: %w", err)
	}

	server, err := FindServerByName(backupConfig.Server)
	if err != nil {
		return fmt.Errorf("Can't find server: %w", err)
	}

	var sshConfig *ssh.ClientConfig = nil

	if server.Password != "" {
		sshConfig = &ssh.ClientConfig{
			User: server.User,
			Auth: []ssh.AuthMethod{
				ssh.Password(server.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else if server.IdentityFile != "" {
		authMethod, err2 := loadPrivateKey(server.IdentityFile)
		if err2 != nil {
			return fmt.Errorf("Failed to load private key: %w", err)
		}

		sshConfig = &ssh.ClientConfig{
			User: server.User,
			Auth: []ssh.AuthMethod{
				authMethod,
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else {
		return fmt.Errorf("Can't find password or identity file")
	}

	addr := fmt.Sprintf("%s:%d", server.Host, server.Port)
	sshConn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("Failed to dial SSH: %w", err)
	}
	log.Printf("Connected to server: %s", addr)
	defer sshConn.Close()

	client, err := sftp.NewClient(sshConn)
	if err != nil {
		return fmt.Errorf("Failed to create SFTP client: %w", err)
	}
	defer client.Close()

	err = uploadDirectory(client, latestBackup.Path, backupConfig.Path)
	if err != nil {
		return fmt.Errorf("Failed to upload directory: %w", err)
	}

	return nil
}

// Upload a single file to the remote server
func uploadFile(client *sftp.Client, localFilePath, remoteDir string) error {
	// Открытие локального файла для чтения
	localFile, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("Failed to open local file: %w", err)
	}
	defer localFile.Close()

	// Определение удаленного пути
	remoteFilePath := filepath.Join(remoteDir, filepath.Base(localFilePath))

	// Создание удаленного файла для записи
	remoteFile, err := client.Create(remoteFilePath)
	if err != nil {
		return fmt.Errorf("Failed to create remote file: %w", err)
	}
	defer remoteFile.Close()

	// Копирование файла
	if _, err = io.Copy(remoteFile, localFile); err != nil {
		return fmt.Errorf("Failed to copy file: %w", err)
	}

	log.Printf("Uploaded file %s to %s", localFilePath, remoteFilePath)
	return nil
}

// Upload a directory recursively to the remote server
func uploadDirectory(client *sftp.Client, localDir, remoteDir string) error {
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return fmt.Errorf("Failed to read local directory: %w", err)
	}

	// Создание удаленной директории, если ее нет
	err = client.MkdirAll(remoteDir)
	if err != nil {
		return fmt.Errorf("Failed to create remote directory: %w", err)
	}
	log.Printf("Created remote directory: %s", remoteDir)

	for _, entry := range entries {
		localPath := filepath.Join(localDir, entry.Name())
		remotePath := filepath.Join(remoteDir, entry.Name())

		if entry.IsDir() {
			err = uploadDirectory(client, localPath, remotePath)
			if err != nil {
				return err
			}
		} else {
			err = uploadFile(client, localPath, remoteDir)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func CheckForChangesForBackupConfig(backupConfigName string) (bool, error) {
	// Найти конфигурацию бэкапа по имени
	backupConfig, err := FindBackupConfigByName(backupConfigName)
	if err != nil {
		return false, fmt.Errorf("Can't find backup config: %w", err)
	}

	// Найти сервер, связанный с конфигурацией бэкапа
	server, err := FindServerByName(backupConfig.Server)
	if err != nil {
		return false, fmt.Errorf("Can't find server: %w", err)
	}

	// Настройка SSH-конфигурации
	var sshConfig *ssh.ClientConfig
	if server.Password != "" {
		sshConfig = &ssh.ClientConfig{
			User: server.User,
			Auth: []ssh.AuthMethod{
				ssh.Password(server.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else if server.IdentityFile != "" {
		authMethod, err := loadPrivateKey(server.IdentityFile)
		if err != nil {
			return false, fmt.Errorf("Failed to load private key: %w", err)
		}
		sshConfig = &ssh.ClientConfig{
			User: server.User,
			Auth: []ssh.AuthMethod{
				authMethod,
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else {
		return false, fmt.Errorf("Can't find password or identity file")
	}

	// Подключение к серверу по SSH
	addr := fmt.Sprintf("%s:%d", server.Host, server.Port)
	sshConn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return false, fmt.Errorf("Failed to dial SSH: %w", err)
	}
	defer sshConn.Close()

	// Создание SFTP-клиента
	client, err := sftp.NewClient(sshConn)
	if err != nil {
		return false, fmt.Errorf("Failed to create SFTP client: %w", err)
	}
	defer client.Close()

	// Получение последнего бэкапа для данной конфигурации бэкапа
	latestBackup := getLatestBackup(backupConfigName)
	if latestBackup == nil {
		return false, fmt.Errorf("No backup found for config: %s", backupConfigName)
	}

	// Сравнение хеш-сумм файлов
	for _, backupedFile := range latestBackup.Files {
		remoteFilePath := filepath.Join(backupConfig.Path, backupedFile.RelativePath)
		remoteFileHash, err := CalculateRemoteFileHash(client, remoteFilePath)
		if err != nil {
			return false, fmt.Errorf("Error calculating remote file hash: %w", err)
		}

		if remoteFileHash != backupedFile.Hash {
			// Если хеши не совпадают, значит файл изменился
			return true, nil
		}
	}

	// Если изменений не найдено
	return false, nil
}

func CalculateRemoteFileHash(client *sftp.Client, remoteFilePath string) (string, error) {
	remoteFile, err := client.Open(remoteFilePath)
	if err != nil {
		return "", fmt.Errorf("Failed to open remote file: %w", err)
	}
	defer remoteFile.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, remoteFile); err != nil {
		return "", fmt.Errorf("Failed to calculate hash: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func ServiceLoop() {
	log.Printf("Running as service")
	for {
		for _, server := range config.Servers {
			log.Printf("Checking server: %s", server.Name)
			backupsConfigs := FindBackupConfigsWithServerName(server.Name)

		BACKUP_CONFIG:
			for _, backupConfig := range backupsConfigs {
				log.Printf("Checking backup config: %s", backupConfig.Name)

				backup := getLatestBackup(backupConfig.Name)

				if backup == nil {
					log.Printf("No backups found for config: %s", backupConfig.Name)
					log.Printf("[!] Making backup")

					err := makeBackup(backupConfig.Name)
					if err != nil {
						log.Printf("Failed to make backup: %w", err)
						continue BACKUP_CONFIG
					}
				} else {
					log.Printf("Checking for changes on server for backup config: %s", backupConfig.Name)

					hasChanges, err := CheckForChangesForBackupConfig(backupConfig.Name)
					if err != nil {
						log.Printf("Failed to check for changes on server for backup config: %w", err)
						continue BACKUP_CONFIG
					}

					if hasChanges {
						log.Printf("[!] Files have been modified, making backup...")
						err := makeBackup(backupConfig.Name)
						if err != nil {
							log.Printf("Failed to make backup: %w", err)
							continue BACKUP_CONFIG
						}
					}
				}
			}
		}
		log.Printf("Waiting %s...", config.Settings.CheckChangesTimeout)
		time.Sleep(checkChangesTimeout)
	}
}

func main() {
	argConfigPath = flag.String("config", "./config.yaml", "Config file path")
	runAsService = flag.Bool("run_as_service", false, "Run as service")
	argBackupServerName = flag.String("backup_server", "", "Command for forsing backup server, arg as server name")
	argBackupName = flag.String("backup", "", "Command for forsing backup, arg as backup name")
	argUploadLatestBackup = flag.String("upload_latest_backup", "", "Command for uploading latest backup, arg as backup name")
	argUploadLatestServerBackup = flag.String("upload_latest_server_backup", "", "Command for uploading latest server backup, arg as server name")

	flag.Parse()

	log.Printf("argConfigPath: %#v", *argConfigPath)

	err := LoadConfig(*argConfigPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	err = LoadBackupsDatabase()
	if err != nil {
		log.Fatalf("Error loading backups database: %v", err)
	}

	if *argBackupServerName != "" {
		err = makeServerBackup(*argBackupServerName)
		if err != nil {
			log.Fatalf("Can't make backup: %v", err)
		}
	}

	if *argBackupName != "" {
		err = makeBackup(*argBackupName)
		if err != nil {
			log.Fatalf("Can't make backup: %v", err)
		}
	}

	if *argUploadLatestBackup != "" {
		err = uploadLatestBackup(*argUploadLatestBackup)
		if err != nil {
			log.Fatalf("Can't upload latest backup: %v", err)
		}
	}

	if *argUploadLatestServerBackup != "" {
		err = uploadLatestServerBackup(*argUploadLatestServerBackup)
		if err != nil {
			log.Fatalf("Can't upload latest server backup: %v", err)
		}
	}

	if *runAsService {
		ServiceLoop()
	}
}
