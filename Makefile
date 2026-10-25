.PHONY: build test vet fmt clean

BINARY := bin/vecmap

build:
	go build -o $(BINARY) ./cmd/vecmap

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

# clean 只清理构建产物；扫描数据默认保存在 ~/.vecmap/vecmap.db，
# 如需清理本地会话数据请显式执行: rm -f ~/.vecmap/vecmap.db*
clean:
	rm -rf bin
