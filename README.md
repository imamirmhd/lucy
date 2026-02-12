# Lucy: Stealth HTTP/HTTPS Tunnel

**Lucy** (`v0.1.0`) is a high-performance, stealthy tunnel designed to bypass firewalls and Deep Packet Inspection (DPI) systems. It encapsulates arbitrary TCP/UDP traffic within valid, customizable HTTP/HTTPS requests, making it indistinguishable from normal web browsing.

## Key Features

*   **Browser Impersonation**: Mimics Chrome/Firefox/Safari signatures with customizable headers and User-Agents.
*   **Protocol Simulation**: Fully compliant HTTP/1.1 handshake with `Connection: Upgrade`.
*   **Traffic Shaping**: Randomized packet timing, padding, and dummy traffic to defeat statistical analysis.
*   **SNI/Host Rotation**: Client automatically rotates through a list of allowed domains (e.g., `google.com`, `cloudflare.com`) to bypass SNI blocking.
*   **Intelligent Monitoring**: Background health checks detect throttling or blocking and automatically rotate connections.
*   **Redirect Mode**: Unauthorized server connections are redirected (HTTP 301) to a decoy website.
*   **Multiple Proxies**: Built-in SOCKS5 server and simultaneous Port Forwarding support.

---

## Installation

### From Source
Requirements: Go 1.18+

```bash
# Build binaries
make build

# Install to /usr/local/bin
sudo make install
```

---

## Quick Start (Wizard)

The easiest way to configure Lucy is using the interactive wizard.

### 1. Server Setup
```bash
lucy-server wizard
```
*   **Hostname**: Your server's public domain (e.g., `vpn.example.com`).
*   **Transport**: Select `https` for encrypted stealth.
*   **Certificates**: The wizard can auto-generate self-signed certs.
*   **Stealth**: Enable to activate traffic shaping.

### 2. Client Setup
```bash
lucy-client wizard
```
*   **Server**: IP:Port of your Lucy server.
*   **Transport**: Must match server (e.g., `https`).
*   **SNI List**: Enter domains to masquerade as (e.g., `www.google.com,www.microsoft.com`).
*   **Proxies**: Set up SOCKS5 (default `:1080`) or Port Forwarding.

---

## Configuration Reference

Lucy uses a unified **TOML** configuration file (`config.toml`). Below is a detailed explanation of every parameter.

### 1. Server Configuration `[server]`

Defines listening ports, TLS settings, and user access.

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `listen` | string | `0.0.0.0:443` | The address and port to bind to. Port 443 is recommended for HTTPS stealth. |
| `hostname` | string | - | The server's public hostname. Used for certificate generation. |
| `cert_file` | string | `server.crt` | Path to the TLS certificate file (PEM format). |
| `key_file` | string | `server.key` | Path to the TLS private key file (PEM format). |
| `log_level` | string | `info` | Logging verbosity: `debug`, `info`, `warn`, `error`. |

#### Users `[[server.users]]`
You can define multiple users.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `username` | string | Authentication username. |
| `secret` | string | Shared secret key for HMAC authentication. |
| `whitelist` | list | List of allowed client IP CIDRs (e.g., `["0.0.0.0/0"]` for any). |
| `logging` | bool | If `true`, connections from this user are logged. |

**Example:**
```toml
[server]
listen = "0.0.0.0:443"
cert_file = "/etc/lucy/certs/server.crt"
key_file = "/etc/lucy/certs/server.key"

[[server.users]]
username = "admin"
secret = "my-secure-secret-123"
whitelist = ["0.0.0.0/0"]
```

### 2. Client Configuration `[client]`

Defines connection targets and local proxy interfaces.

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `server` | string | - | The remote server address (IP:Port or Host:Port). |
| `username` | string | - | Must match a user defined on the server. |
| `secret` | string | - | Must match the user's secret. |
| `ca_cert` | string | - | Path to the CA certificate to verify the server. Empty to use system roots. |
| `insecure_skip_verify` | bool | `false` | If `true`, disables TLS certificate verification (INSECURE). |
| `reconnect_delay` | duration | `2s` | Initial wait time before reconnecting after a failure. |
| `max_reconnect_delay` | duration | `30s` | Maximum wait time for exponential backoff. |

#### SOCKS5 Proxy `[[client.socks]]`
Creates a local SOCKS5 server.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `listen` | string | Local address to listen on (e.g., `127.0.0.1:1080`). |
| `username` | string | (Optional) Username for SOCKS5 auth. |
| `password` | string | (Optional) Password for SOCKS5 auth. |

#### Port Forwarding `[[client.forward]]`
Maps a local port to a remote destination through the tunnel.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `listen` | string | Local address (e.g., `127.0.0.1:8080`). |
| `forward` | string | Remote target (e.g., `internal-db:5432`). |
| `protocol` | string | `tcp` or `udp`. |

### 3. Transport Configuration `[transport]`

This section controls **Stealth** and **Impersonation**. It defines *how* the connection looks to the outside world.

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `type` | string | `https` | Transport mode: `https` (recommended), `http`, or `redirect`. |
| `hosts` | list | - | **Critical**: List of SNI/Host headers to use. The client picks one randomly per connection. e.g., `["google.com", "bing.com"]`. |
| `user_agent` | string | - | The HTTP User-Agent header string to send. |
| `headers` | map | - | Custom HTTP headers to add to every handshake request (e.g., `{"Accept-Language" = "en-US"}`). |
| `request_paths` | list | `["/"]` | List of URL paths to simulate (e.g., `["/api/v1", "/search"]`). |
| `methods` | list | - | List of allowed HTTP methods (e.g., `["GET", "POST"]`). |
| `redirect_to` | string | - | **Server Only**: If `type="redirect"`, specific the URL to redirect unauthorized traffic to (HTTP 301). |

**Example:**
```toml
[transport]
type = "https"
hosts = ["www.google.com", "www.cloudflare.com"]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..."
request_paths = ["/search", "/images", "/api/data"]
methods = ["GET", "POST"]
headers = { "Accept-Encoding" = "gzip, deflate" }
```

### 4. Stealth & Traffic Shaping `[stealth]`

Controls low-level traffic obfuscation.

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enabled` | bool | `true` | Master switch for traffic shaping. |
| `min_delay_ms` | int | `50` | Minimum random delay injected between packets. |
| `max_delay_ms` | int | `500` | Maximum random delay. |
| `padding_sizes` | list | `[...]` | List of target sizes (bytes) for packet padding. |
| `dummy_probability` | float | `0.1` | Probability (0.0 - 1.0) of sending dummy/chaff traffic to normalize flow volume. |

---

## Operational Workflows

### Running Manually
Useful for debugging or temporary tunnels.
```bash
lucy-server run -c config.toml
lucy-client run -c config.toml
```

### Systemd Service (Production)
Lucy has built-in service management commands.

**Install Service:**
```bash
sudo lucy-server service install /etc/lucy/config.toml
```

**Manage Service:**
```bash
sudo lucy-server service start
sudo lucy-server service stop
sudo lucy-server service status
sudo lucy-server service logs -n 100
```
*(Replace `lucy-server` with `lucy-client` for client management)*

---

## Testing & Diagnostics

Lucy includes tools to verify your tunnel's performance and invisibility.

### 1. Connection Health (`ping`)
Measures application-layer latency (RTT) through the tunnel.
```bash
lucy-client ping -c config.toml -n 5
# Output:
# PING 192.168.1.5 (5 pings):
#   seq=1 rtt=45ms
#   seq=2 rtt=48ms
# ...
```

### 2. Throughput Benchmark (`benchmark`)
Floods the tunnel to estimate maximum throughput and stability under load.
```bash
lucy-client benchmark -c config.toml -t 10s
# Output:
# Benchmark: 50000 messages in 10s (5000 req/s)
```

### 3. Status Report (`status`)
Dumps current configuration, proxy listen ports, and connection state.
```bash
lucy-client status -c config.toml
```

---

## Security Best Practices

1.  **Always use HTTPS**: The `http` transport mode provides no encryption for the tunnel headers themselves (though the inner stream is encrypted). Use `https` for full stealth.
2.  **Use Valid SNI Hosts**: When configuring `hosts`, use domains that realistically run on the target IP or use a CDN fronting setup.
3.  **Rotate User Agents**: Periodically update the `user_agent` string in your config to match modern browser versions.
4.  **Redirect Mode**: On the server, consider setting `type="redirect"` and `redirect_to="https://google.com"` (or similar). This ensures that any active probe sent by a censor to your server port will receive a confusing 301 Redirect instead of a connection drop.
