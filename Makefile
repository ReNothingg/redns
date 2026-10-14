VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || date +%Y.%m.%d)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test dist deploy clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/redns ./cmd/redns

test:
	go vet ./...
	go test -race ./...

dist:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/redns-linux-amd64 ./cmd/redns
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/redns-linux-arm64 ./cmd/redns

deploy:
	./deploy/deploy.sh $(HOST) --domain $(DOMAIN) $(if $(EMAIL),--email $(EMAIL))

clean:
	rm -rf bin dist
