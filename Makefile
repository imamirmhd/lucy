.PHONY: build release clean

GO ?= /usr/local/go/bin/go
VERSION := v0.1.0
DIST := dist

build:
	$(GO) build -o lucy ./cmd/

release:
	@./scripts/build-release.sh

clean:
	rm -rf $(DIST) lucy
