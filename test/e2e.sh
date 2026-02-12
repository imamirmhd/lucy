#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[TEST] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

cleanup() {
    log "Cleaning up processes..."
    pkill -f lucy-server || true
    pkill -f lucy-client || true
    pkill -f python3 || true
    # Don't delete test dir as user might want to inspect logs
}
trap cleanup EXIT

# Ensure we are in the project root or test dir
# If running from root, cd into test
if [ -d "test" ]; then
    cd test
fi

log "Setting up test environment in $(pwd)..."
mkdir -p certs

# 1. Build
log "Building binaries..."
# Use -buildvcs=false to avoid error in non-git envs or limited envs
go build -buildvcs=false -o ../lucy-server ../cmd/lucy-server
go build -buildvcs=false -o ../lucy-client ../cmd/lucy-client

# 2. Generate Certs
log "Generating certificates..."
../lucy-server gencerts -hostname localhost -output-dir ./certs

# 3. Create Server Config
cat > server.toml <<EOF
[server]
listen = "127.0.0.1:9443"
hostname = "localhost"
cert_file = "./certs/server.crt"
key_file = "./certs/server.key"
log_level = "debug"

[[server.users]]
username = "testuser"
secret = "testsecret"
whitelist = ["0.0.0.0/0"]
logging = true

[transport]
type = "https"
hosts = ["localhost"]
mix_host = "random"
user_agent = "lucy-test-agent"

[stealth]
enabled = true
EOF

# 4. Create Client Config
cat > client.toml <<EOF
[client]
server = "127.0.0.1:9443"
username = "testuser"
secret = "testsecret"
ca_cert = "./certs/ca.crt"
insecure_skip_verify = true
reconnect_delay = "1s"
max_reconnect_delay = "5s"

[[client.socks]]
listen = "127.0.0.1:10800"
username = ""
password = ""

[transport]
type = "https"
hosts = ["localhost"]
mix_host = "random"
user_agent = "lucy-test-agent"

[stealth]
enabled = true
EOF

# 5. Start Dummy HTTP Service
log "Starting dummy HTTP service on port 9090..."
mkdir -p www
echo "Hello from Lucy Target" > www/index.html
# Use python3 http.server
python3 -m http.server 9090 --directory www > http.log 2>&1 &
PID_HTTP=$!
sleep 2

# 6. Start Server
log "Starting Lucy Server..."
../lucy-server run -c server.toml -debug > server.log 2>&1 &
PID_SERVER=$!
sleep 2

# 7. Start Client
log "Starting Lucy Client..."
../lucy-client run -c client.toml -debug > client.log 2>&1 &
PID_CLIENT=$!
sleep 5

# 8. Test Connectivity (Ping)
log "Testing Ping..."
../lucy-client ping -c client.toml -n 3 || error "Ping failed"

# 9. Test Status
log "Testing Status..."
../lucy-client status -c client.toml || error "Status check failed"

# 10. Test Throughput (Benchmark)
log "Testing Benchmark..."
../lucy-client benchmark -c client.toml -t 2s || error "Benchmark failed"

# 11. Test SOCKS5 Proxy
log "Testing SOCKS5 Proxy (curl -> lucy -> httpd)..."
# We need to wait a bit for SOCKS to come up
sleep 2
RESPONSE=$(curl -s --socks5-hostname 127.0.0.1:10800 http://localhost:9090/index.html)

if [[ "$RESPONSE" == *"Hello from Lucy Target"* ]]; then
    log "SOCKS5 Test PASSED: Received correct response"
else
    log "Response was: $RESPONSE"
    error "SOCKS5 Test FAILED"
fi

log "All tests passed successfully!"
