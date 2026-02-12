.PHONY: all build clean install

all: build

build:
	go build -buildvcs=false -o lucy-server ./cmd/lucy-server
	go build -buildvcs=false -o lucy-client ./cmd/lucy-client

clean:
	rm -f lucy-server lucy-client

install: build
	cp lucy-server /usr/local/bin/
	cp lucy-client /usr/local/bin/
	mkdir -p /etc/lucy
	mkdir -p /etc/lucy/configs
	mkdir -p /etc/lucy/certs
	@if [ ! -f /etc/lucy/config.toml ]; then \
		cp config.toml /etc/lucy/config.toml; \
		echo "Installed default config to /etc/lucy/config.toml"; \
	fi

install-services:
	cp dist/lucy-server.service /etc/systemd/system/
	cp dist/lucy-client.service /etc/systemd/system/
	systemctl daemon-reload
	@echo "Services installed. Enable with:"
	@echo "  systemctl enable --now lucy-server"
	@echo "  systemctl enable --now lucy-client"

uninstall:
	systemctl stop lucy-server 2>/dev/null || true
	systemctl stop lucy-client 2>/dev/null || true
	systemctl disable lucy-server 2>/dev/null || true
	systemctl disable lucy-client 2>/dev/null || true
	rm -f /usr/local/bin/lucy-server /usr/local/bin/lucy-client
	rm -f /etc/systemd/system/lucy-server.service
	rm -f /etc/systemd/system/lucy-client.service
	systemctl daemon-reload
	@echo "Note: /etc/lucy was NOT removed. Delete manually if needed."
