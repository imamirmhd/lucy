# Lucy: Stealth HTTP/HTTPS Tunnel

**Lucy** is a high-performance, stealthy tunnel designed to bypass firewalls and DPI (Deep Packet Inspection) systems by masquerading traffic as legitimate HTTP/HTTPS web browsing.

It encapsulates arbitrary TCP/UDP traffic within standard HTTP requests, employing techniques such as "Browser Impersonation," SNI/Host rotation, and intelligent traffic shaping to blend in with normal internet activity.

## Features

### Transport & Stealth
*   **HTTP/HTTPS Transport**: Wraps tunnel data in standard HTTP/1.1 requests with `Connection: Upgrade` headers.
*   **Browser Impersonation**: Configurable User-Agent, Accept headers, and randomized request paths/methods (GET/POST) to mimic real browsers.
*   **SNI/Host Rotation**: Automatically rotates through a list of SNI hosts (e.g., `www.google.com`, `www.microsoft.com`) to bypass domain filtering.
*   **Traffic Shaping**: Delays packets and injects padding to confuse timing-based analysis.
*   **Fake Responses**: Authentication failures trigger realistic 404/200 HTML pages or 301 redirects to decoy sites.

### Connectivity
*   **SOCKS5 Proxy**: Built-in SOCKS5 server for easy browser/app integration.
*   **Port Forwarding**: Forward local ports to remote destinations (TCP/UDP).
*   **Health Monitoring**: Continuous latency checks; automatically disconnects and rotates hosts upon detection of throttling or interference.
*   **Auto-Reconnect**: Robust reconnection logic with exponential backoff.

### Management
*   **Unified Configuration**: Single TOML file for all settings (`server`, `client`, `transport`, `stealth`).
*   **Wizard**: Interactive setup wizard (`lucy-server wizard`, `lucy-client wizard`).
*   **Systemd Integration**: Built-in commands to install, manage, and monitor systemd services.
*   **Diagnostics**: Integrated `ping`, `status`, and `benchmark` tools.

## Installation

### From Source
```bash
make build
sudo make install
```
This builds `lucy-server` and `lucy-client` and installs them to `/usr/local/bin/`.

## Quick Start

### 1. Server Setup
Run the wizard to generate a secure configuration:
```bash
lucy-server wizard
```
Follow the prompts to:
1.  **Transport**: Choose `https` for maximum stealth.
2.  **Certificates**: Auto-generate self-signed certs or provide your own.
3.  **Users**: Create a username and secret.

Start the server:
```bash
lucy-server run -c config_server.toml
```

### 2. Client Setup
Run the client wizard:
```bash
lucy-client wizard
```
Follow the prompts to:
1.  **Server**: Enter your server's IP:Port (e.g., `203.0.113.1:443`).
2.  **Transport**: Match the server's transport type (`https`).
3.  **SNI/Host List**: Enter domains to mimic (e.g., `www.google.com,www.cloudflare.com`).
4.  **Credentials**: Enter the username/secret created on the server.

Start the client:
```bash
lucy-client run -c config_client.toml
```

### 3. Usage
Once connected, configure your browser or application to use the SOCKS5 proxy (default: `127.0.0.1:1080`).

## Configuration Reference

### Transport Configuration (`[transport]`)
This section defines how traffic is disguised.

```toml
[transport]
type = "https"                  # "http", "https", or "redirect"
hosts = ["www.google.com"]      # SNI/Host header values to rotate
mix_host = "random"             # "random" or "round-robin"
user_agent = "Mozilla/5.0..."   # browser string to impersonate
redirect_to = "https://example.com" # Target for 301 redirects (server-side)
```

### Stealth Configuration (`[stealth]`)
Controls timing and padding.

```toml
[stealth]
enabled = true
min_delay_ms = 50
max_delay_ms = 500
padding_sizes = [4096, 8192]    # Randomly pad packets to these sizes
dummy_probability = 0.1         # Chance to send empty "keep-alive" traffic
```

## Tools & Diagnostics

### Check Connection Health
Measure latency to the server:
```bash
lucy-client ping -c config.toml
```

### Throughput Benchmark
Test link speed and stability:
```bash
lucy-client benchmark -t 10s -c config.toml
```

### Service Status
View connection details and active tunnels:
```bash
lucy-client status -c config.toml
```

## Systemd Service Management

Install configuration as a background service:
```bash
sudo lucy-client service install config.toml
sudo lucy-client service start
```

## License
MIT License. See LICENSE for details.
