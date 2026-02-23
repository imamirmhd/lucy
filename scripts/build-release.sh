#!/usr/bin/env bash
set -e

# gopacket/pcap uses CGO - cross-compile only works for same OS.
# Full multi-platform: use GitHub Actions (see .github/workflows/release.yml)
GO="${GO:-/usr/local/go/bin/go}"
DIST=dist
mkdir -p "$DIST"

# Build current platform (works on Linux with libpcap-dev)
echo "Building lucy-linux-amd64 ..."
"$GO" build -ldflags="-s -w" -o "$DIST/lucy-linux-amd64" ./cmd/
echo "Done. Build in $DIST/"
