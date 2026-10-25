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

clean:
	rm -rf bin vecmap.db vecmap.db-wal vecmap.db-shm
