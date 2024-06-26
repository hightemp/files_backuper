# Имя вашего бинарника
BINARY_NAME=files_backuper

# Указание путей
CMD_DIR=./cmd/files_backuper
BUILD_DIR=./build

# Флаги и параметры
GO=go

.PHONY: all build test clean run

# По умолчанию выполняется сборка
all: build

# Сборка проекта
build: clean
	mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)/main.go

# Запуск тестов
test:
	$(GO) test ./...

# Очистка скомпилированных файлов
clean:
	rm -f $(BUILD_DIR)/$(BINARY_NAME)

# Запуск проекта
run:
	# $(BUILD_DIR)/$(BINARY_NAME) -config=$(BUILD_DIR)/config.yaml -backup_server=stage
	# $(BUILD_DIR)/$(BINARY_NAME) -config=$(BUILD_DIR)/config.yaml -backup=hlr_rails_common_config
	$(BUILD_DIR)/$(BINARY_NAME) -config=$(BUILD_DIR)/config.yaml -run_as_service

build_and_run: build run