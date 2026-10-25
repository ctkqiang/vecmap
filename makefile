.PHONY: build inspect clean

BUILD_DIR = ./build
DB_FILE = $(HOME)/.vecmap/vecmap.db

clean:
	@echo "正在清理构建目录"
	rm -rf $(BUILD_DIR)
	rm -f $(DB_FILE) $(DB_FILE)-wal $(DB_FILE)-shm
	@echo "构建目录清理完成"

inspect:
	@echo "正在检查代码"
	go vet ./...
	@echo "代码检查完成"

build:
	@echo "正在构建vecmap"
	go build -o $(BUILD_DIR)/vecmap cmd/vecmap.go
	@echo "vecmap构建完成"
