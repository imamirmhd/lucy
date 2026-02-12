# Lucy Technical Documentation (v0.1.0)

## Architecture Overview

Lucy operates as a point-to-point tunnel that encapsulates data streams within HTTP/1.1 frames. It is designed to look like a legitimate web browsing session to an observer.

### Protocol Stack
1.  **Application Layer**: SOCKS5 / Port Forwarding
2.  **Framing Layer**: Custom binary framing (Channel ID + Payload)
3.  **Transport Layer**: HTTP/1.1 Upgrade Request (WebSocket-like)
4.  **Encryption Layer**: TLS 1.2+ (with SNI)
5.  **Network Layer**: TCP/IP

## Transport Mechanisms

### HTTP/HTTPS Mode
The client initiates a connection using a standard HTTP request:

```http
GET / HTTP/1.1
Host: www.google.com
User-Agent: Mozilla/5.0 ...
Connection: Upgrade
Upgrade: websocket
X-Lucy-Token: <HMAC-SHA256>
```

-   **SNI Rotation**: The TLS ClientHello SNI extension is set to a random host from the `hosts` config list.
-   **Host Header**: Matches the SNI value to pass HTTP Host header checks.
-   **Auth Token**: A time-based HMAC token is included in a custom header (or cookie) to authenticate the session *before* tunnel establishment.

### Redirect Mode
If the server receives a request with an invalid token or on a non-tunnel path, it can be configured to respond with:
-   **404 Not Found**: A realistic Nginx/Apache error page.
-   **301 Moved Permanently**: Redirects the client to a configured decoy URL (e.g., `https://www.google.com`), confusing active probes.

## Connection Lifecycle

1.  **Handshake**: Client connects via TCP/TLS and sends the HTTP Upgrade request.
2.  **Authentication**: Server verifies `X-Lucy-Token`.
    -   *Success*: Server responds with `101 Switching Protocols` and hijacks the connection for raw binary stream.
    -   *Failure*: Server responds with 404/301 and closes connection.
3.  **Tunneling**: Multplexed binary frames are exchanged.
    -   `FrameData`: Payload for a specific channel (SOCKS connection).
    -   `FramePing/Pong`: Keep-alive and latency measurement.
4.  **Rotation**: Client monitors latency (`Ping`). If thresholds are exceeded, it cleanly closes the connection and initiates a NEW handshake using a *different* SNI host.

## Security

### Authentication
-   **HMAC-SHA256**: Uses a shared secret to sign the timestamp.
-   **Replay Protection**: Server rejects tokens older than 5 minutes.

### Encryption
-   **TLS 1.3**: Recommended.
-   **Perfect Forward Secrecy**: Enforced by default TLS cipher suites.

### Anti-DPI Features
-   **Padding**: Frames can be padded to standard block sizes to hide protocol signatures.
-   **Timing Jitter**: Randomized delays between packets to defeat timing analysis.
-   **Traffic Morphing**: Mixing GET and POST requests to look like interactive browsing.

## Benchmarking & Monitoring

Lucy includes an internal `debug` package that performs:
-   **Latency**: RTT measurement using dedicated PING frames.
-   **Throughput**: Saturation testing by flooding the tunnel with data frames and measuring receiver rate.
-   **Health**: Recurring checks that trigger failover logic.
