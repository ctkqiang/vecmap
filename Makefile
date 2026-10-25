.PHONY: build test vet fmt clean manpage

BINARY := build/vecmap

build:
	@echo	"正在构建 $(BINARY)..."
	go build -o $(BINARY) ./cmd/vecmap

test:
	@echo	"正在测试 $(BINARY)..."
	go test ./...

vet:
	@echo	"正在检查 $(BINARY)..."
	go tool vet ./...
	go vet ./...

fmt:
	@echo	"正在格式化 $(BINARY)..."
	go fmt ./...
	gofmt -l .

# manpage 将内嵌手册页同步到 docs/vecmap.1，供 man(1) 或安装使用。
manpage:
	@echo	"正在同步手册页..."
	cp internal/app/data/vecmap.1 docs/vecmap.1
	cp internal/app/data/vecmap.zh.1 docs/vecmap.zh.1

# clean 只清理构建产物；扫描数据默认保存在 ~/.vecmap/vecmap.db，
# 如需清理本地会话数据请显式执行: rm -f ~/.vecmap/vecmap.db*
clean:
	@echo	"正在清理构建产物..."
	rm -rf bin
