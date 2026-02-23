# lucy

A high-performance bidirectional packet-level proxy that tunnels traffic over KCP using raw TCP packets. Built for maximum throughput with encrypted transport, SOCKS5 proxy support, port forwarding, and stealth mode with IP address spoofing.

## How It Works

lucy operates at the packet level using **pcap** to craft raw TCP packets that carry KCP-encrypted payloads. Traffic appears as normal TCP to network devices, but the actual transport is KCP — providing reliable, low-latency delivery with tunable congestion control.

```
┌─────────┐         raw TCP packets (KCP payload)         ┌─────────┐
│  Client  │ ──────────────────────────────────────────── │  Server  │
│          │         pcap ← Ethernet → pcap               │          │
└────┬─────┘                                              └────┬─────┘
     │                                                         │
  SOCKS5 / Forward                                   Dials target hosts
  (local listeners)                                  (TCP / UDP)
```

## Requirements

- Linux (primary), macOS, or Windows (with Npcap)
- Root / administrator privileges (raw socket access)
- `libpcap-dev` (`apt install libpcap-dev` / `yum install libpcap-devel`)

## Installation

```bash
git clone https://github.com/imamirmhd/lucy.git
cd lucy
go build -o lucy ./cmd/
```

---

## Commands

### `lucy run`

Starts the client or server based on the configuration file.

```
lucy run [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | `config.yaml` | Path to the YAML configuration file |

**Examples:**

```bash
# Start with default config
lucy run

# Start with custom config
lucy run -c /etc/lucy/server.yaml
```

---

### `lucy monitor`

Global system monitor. Launches **glances** for a full system overview, or **iftop** for live network traffic.

```
lucy monitor [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--connections` | `-c` | `false` | Show live network traffic via iftop |

**Examples:**

```bash
# System overview (glances)
lucy monitor

# Network traffic monitor (iftop)
lucy monitor -c
```

**Dependencies:** Install `glances` (`pip install glances` or `apt install glances`) and/or `iftop` (`apt install iftop`).

---

### `lucy dump`

Raw packet dumper — captures and displays TCP payload hex dumps on the configured interface and port. Useful for debugging.

```
lucy dump [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | `config.yaml` | Path to a **server** configuration file |

**Example:**

```bash
lucy dump -c server.yaml
```

> **Note:** Requires a server-role configuration file.

---

### `lucy ping`

Sends a single raw TCP packet with a custom payload. Useful for testing connectivity.

```
lucy ping [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | `config.yaml` | Path to a **client** configuration file |
| `--payload` | | `PING` | Custom string payload to send |

**Example:**

```bash
lucy ping -c client.yaml --payload "HELLO"
```

> **Note:** Requires a client-role configuration file.

---

### `lucy secret`

Generates a cryptographically secure 32-byte (256-bit) hex-encoded key for use in the encryption configuration.

```bash
lucy secret
# Output: a1b2c3d4e5f6...  (64 hex characters)
```

---

### `lucy iface`

Lists all available network interfaces with their MAC addresses and IP addresses.

```bash
lucy iface
```

**Example output:**

```
Available network interfaces:
  eth0: aa:bb:cc:dd:ee:ff
    10.0.0.100/24
    fe80::1/64
  lo: 
    127.0.0.1/8
    ::1/128
```

---

### `lucy wizard`

Interactive configuration wizard that guides you through creating a `config.yaml` file step-by-step.

```bash
lucy wizard
```

---

### `lucy version`

Prints build information.

```bash
lucy version
```

---

## Configuration Reference

lucy uses a YAML configuration file. Below is every parameter with its type, default value, and description.

### `role`

```yaml
role: "client"  # Required. "client" or "server"
```

---

### `log`

```yaml
log:
  level: "none"  # Log verbosity level
```

| Parameter | Type | Default | Values |
|-----------|------|---------|--------|
| `level` | string | `none` | `none`, `debug`, `info`, `warn`, `error`, `fatal` |

---

### `listen` (Server Only)

The address and port the server listens on for incoming connections.

```yaml
listen:
  addr: ":9999"  # Listen address (host:port)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `addr` | string | Yes (server) | Bind address. Use `:PORT` for all interfaces |

---

### `server` (Client Only)

The remote lucy server to connect to.

```yaml
server:
  addr: "10.0.0.100:9999"  # Server address (host:port)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `addr` | string | Yes (client) | Remote server `IP:PORT` |

---

### `network`

Network interface and raw socket configuration. This is the core of lucy's packet-level operation.

```yaml
network:
  interface: "eth0"               # Network interface name
  # guid: "\\Device\\NPF_{...}"  # Windows only (Npcap device GUID)
  
  ipv4:
    addr: "10.0.0.100:9999"          # Local IPv4 address and port
    router_mac: "aa:bb:cc:dd:ee:ff"  # Gateway MAC address
  
  ipv6:                               # Optional
    addr: "[2001:db8::1]:9999"        # Local IPv6 address and port
    router_mac: "aa:bb:cc:dd:ee:ff"   # Gateway MAC address
  
  tcp:
    local_flag: ["PA"]    # Outgoing TCP flags
    remote_flag: ["PA"]   # Expected incoming TCP flags (client only)
  
  pcap:
    sockbuf: 4194304   # pcap socket buffer size in bytes
```

#### `network` Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | string | *required* | Network interface name (`eth0`, `en0`, `wlan0`) |
| `guid` | string | — | Windows Npcap device GUID (Windows only) |

#### `network.ipv4` / `network.ipv6`

At least one address family must be configured. If both are used, ports must match.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `addr` | string | Yes (at least one) | `IP:PORT` — use port `0` for random (client) |
| `router_mac` | string | Yes | Gateway/router MAC address (`aa:bb:cc:dd:ee:ff`) |

> **Tip:** Use `lucy iface` to find your interface name and `arp -n` to find your gateway MAC.

#### `network.tcp`

TCP flag combinations for crafted packets. Each flag string is a combination of characters representing TCP flags.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `local_flag` | []string | `["PA"]` | TCP flags for outgoing packets |
| `remote_flag` | []string | `["PA"]` | TCP flags for incoming packets (client only) |

**Flag characters:** `F`=FIN, `S`=SYN, `R`=RST, `P`=PSH, `A`=ACK, `U`=URG, `E`=ECE, `C`=CWR, `N`=NS

**Examples:**

```yaml
tcp:
  local_flag: ["PA"]           # PSH+ACK (default, most common)
  local_flag: ["SA", "PA"]     # Alternate between SYN+ACK and PSH+ACK
  local_flag: ["A"]            # ACK only
```

#### `network.pcap`

| Parameter | Type | Default (client) | Default (server) | Range |
|-----------|------|----------|----------|-------|
| `sockbuf` | int | 4 MB | 8 MB | 1 KB – 100 MB |

> **Tip:** Use powers of 2 (4MB, 8MB, 16MB) for optimal performance.

---

### `transport`

Transport protocol and connection settings.

```yaml
transport:
  protocol: "kcp"    # Transport protocol
  conn: 1            # Number of parallel connections
  tcpbuf: 8192       # TCP copy buffer size (bytes)
  udpbuf: 4096       # UDP copy buffer size (bytes)
  
  kcp:
    # ... KCP settings (see below)
```

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `protocol` | string | — | `kcp` | Transport protocol |
| `conn` | int | `1` | 1–256 | Number of parallel KCP connections |
| `tcpbuf` | int | `8192` | ≥ 4096 | Buffer size for TCP stream copying |
| `udpbuf` | int | `4096` | ≥ 2048 | Buffer size for UDP stream copying |

> **Note:** When a client port is explicitly set (non-zero), only 1 connection is allowed.

---

### `transport.kcp`

KCP protocol tuning. Use preset modes or `manual` for full control.

```yaml
kcp:
  mode: "fast"                    # Preset mode
  mtu: 1350                       # Maximum transmission unit
  rcvwnd: 512                     # Receive window
  sndwnd: 512                     # Send window
  block: "aes"                    # Encryption algorithm
  key: "your-secret-key-here"     # Encryption key
  smuxbuf: 4194304                # SMUX receive buffer
  streambuf: 2097152              # Stream buffer
```

#### Preset Modes

| Mode | NoDelay | Interval | Resend | NoCongestion | WDelay | AckNoDelay |
|------|---------|----------|--------|--------------|--------|------------|
| `normal` | 0 | 40ms | 2 | 1 | true | false |
| `fast` | 0 | 30ms | 2 | 1 | true | false |
| `fast2` | 1 | 20ms | 2 | 1 | false | true |
| `fast3` | 1 | 10ms | 2 | 1 | false | true |
| `manual` | Custom | Custom | Custom | Custom | Custom | Custom |

#### Manual Mode Parameters

Only used when `mode: "manual"`:

| Parameter | Type | Description |
|-----------|------|-------------|
| `nodelay` | int | `0`=disable, `1`=enable. Enables aggressive retransmission |
| `interval` | int | Update timer interval in ms. Lower = more responsive, higher CPU |
| `resend` | int | Fast retransmit trigger. `0`=disabled, `1`=most aggressive, `2`=aggressive |
| `nocongestion` | int | `0`=TCP-like congestion control, `1`=disabled (max speed) |
| `wdelay` | bool | `false`=flush immediately (low latency), `true`=batch writes (throughput) |
| `acknodelay` | bool | `true`=send ACKs immediately (low latency), `false`=batch ACKs |

#### Window & MTU

| Parameter | Type | Default (client) | Default (server) | Range |
|-----------|------|----------|----------|-------|
| `mtu` | int | 1350 | 1350 | 50–1500 |
| `rcvwnd` | int | 512 | 2048 | 1–32768 |
| `sndwnd` | int | 512 | 2048 | 1–32768 |

#### Encryption

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `block` | string | `aes` | Encryption algorithm |
| `key` | string | *required** | Encryption key (must match on both sides) |

\* Required unless `block` is `none` or `null`.

**Supported ciphers:** `aes`, `aes-128`, `aes-128-gcm`, `aes-192`, `salsa20`, `blowfish`, `twofish`, `cast5`, `3des`, `tea`, `xtea`, `xor`, `sm4`, `none`, `null`

> **Tip:** Generate a key with `lucy secret`.

#### Multiplexer Buffers

| Parameter | Type | Default (client) | Default (server) | Range |
|-----------|------|----------|----------|-------|
| `smuxbuf` | int | 4 MB | 8 MB | ≥ 1024 |
| `streambuf` | int | 2 MB | 4 MB | ≥ 1024 |

#### FEC (Forward Error Correction)

Optional. Use for very lossy networks.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dshard` | int | 0 | Data shards for FEC |
| `pshard` | int | 0 | Parity shards for FEC |

---

### `socks5`

SOCKS5 proxy listeners. Multiple entries supported.

```yaml
socks5:
  - listen: "127.0.0.1:1080"
    username: ""       # Optional authentication
    password: ""       # Optional authentication
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `listen` | string | Yes | Bind address (`host:port`) |
| `username` | string | No | SOCKS5 username (leave empty to disable auth) |
| `password` | string | No | SOCKS5 password |

---

### `forward`

Port forwarding rules. Multiple entries supported. TCP and UDP protocols.

```yaml
forward:
  - listen: "127.0.0.1:8080"     # Local bind address
    target: "192.168.1.1:80"     # Remote target (via tunnel)
    protocol: "tcp"              # "tcp" or "udp"
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `listen` | string | Yes | Local bind address (`host:port`) |
| `target` | string | Yes | Remote target address (`host:port`) |
| `protocol` | string | Yes | `tcp` or `udp` |

---

### `stealth` (Client Only)

Stealth mode spoofs source IP addresses on both sides to make traffic analysis harder. Disabled by default. Configured on the client side only — parameters are exchanged with the server during connection setup.

```yaml
stealth:
  real_ip: "192.168.1.100"             # Real client IP (server sends replies here)
  decoy_sources:               # IPs to spoof as packet source (client → server)
    - "1.2.3.4"
    - "5.6.7.8"
  decoy_responses:             # IPs the server will spoof as source (server → client)
    - "9.10.11.12"             # Optional: if omitted, server uses its real IP
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `real_ip` | string | *required** | Real client IP — server delivers reply packets here |
| `decoy_sources` | []string | — | List of IPs to randomly use as source in client→server packets |
| `decoy_responses` | []string | — | List of IPs the server will randomly use as source in server→client packets |

**How it works:**

1. After connection + authentication, the client sends its real address, decoy sources, and desired response addresses to the server
2. The client randomly picks a decoy source IP for each outgoing packet
3. The server randomly picks a decoy response IP for each reply, sending to the client's `real_ip` (port is preserved from the KCP session)
4. If `decoy_responses` is omitted, the server replies using its real IP

\* `real_ip` and at least one `decoy_sources` entry are required to enable stealth mode.

> **Note:** Source IP spoofing requires raw socket access (already required by lucy). Intermediate routers with BCP38/uRPF ingress filtering may drop spoofed packets. This feature works best on networks you control.

> **Note:** No server-side configuration is needed — the server automatically uses the parameters provided by the client during the handshake.


## Full Configuration Examples

### Client

```yaml
role: "client"

log:
  level: "info"

socks5:
  - listen: "127.0.0.1:1080"

forward:
  - listen: "127.0.0.1:8080"
    target: "10.0.0.1:80"
    protocol: "tcp"

network:
  interface: "eth0"
  ipv4:
    addr: "192.168.1.100:0"
    router_mac: "aa:bb:cc:dd:ee:ff"
  tcp:
    local_flag: ["PA"]
    remote_flag: ["PA"]

server:
  addr: "10.0.0.100:9999"

transport:
  protocol: "kcp"
  conn: 1
  kcp:
    mode: "fast2"
    key: "my-secret-key"

# Optional: stealth mode
# stealth:
#   real_ip: "192.168.1.100"
#   decoy_sources:
#     - "1.2.3.4"
#     - "5.6.7.8"
#   decoy_responses:
#     - "9.10.11.12"
```

### Server

```yaml
role: "server"

log:
  level: "info"

listen:
  addr: ":9999"

network:
  interface: "eth0"
  ipv4:
    addr: "10.0.0.100:9999"
    router_mac: "aa:bb:cc:dd:ee:ff"
  tcp:
    local_flag: ["PA"]

transport:
  protocol: "kcp"
  kcp:
    mode: "fast2"
    key: "my-secret-key"
```

---

## Server Firewall Setup

Since lucy uses pcap to bypass the kernel's TCP stack, you **must** configure iptables on the server to prevent the kernel from interfering with lucy's raw packets:

```bash
# Replace 9999 with your listen port
sudo iptables -t raw -A PREROUTING -p tcp --dport 9999 -j NOTRACK
sudo iptables -t raw -A OUTPUT -p tcp --sport 9999 -j NOTRACK
sudo iptables -t mangle -A OUTPUT -p tcp --sport 9999 --tcp-flags RST RST -j DROP
```

> **Warning:** Do not use standard ports (80, 443) as existing iptables rules may conflict.

## License

MIT
