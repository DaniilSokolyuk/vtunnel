# vtunnel

Lightweight reverse tunnel over WebSocket. Expose local services through a remote server.

## How It Works

```
YOUR MACHINE (behind NAT/firewall)                CLOUD SERVER
==================================                ============

+--------------+                        +---------------------------------+
| Web App      |                        |                                 |
| :3000        |<-----+                 |  vtunnel SERVER                 |
+--------------+      |                 |  (listens on localhost only)    |
                      |                 |                                 |
+--------------+      |                 |    localhost:9000 ──┐           |
| API Server   |<-----+                 |    localhost:9001 ──┼── proxy ──┼──> INTERNET
| :8080        |      |                 |    localhost:9002 ──┘           |
+--------------+      |                 |           ^                     |
                      |                 |           |                     |
+--------------+      |                 +-----------│---------------------+
| vtunnel      |      |                             |
| CLIENT       |------+                             |
|              |<===================================┘
+--------------+        WebSocket tunnel
```

**Step by step:**

```
1. CLIENT connects to SERVER via WebSocket
   CLIENT =========================> SERVER (ws://server/tunnel)

2. CLIENT says: "Please open port 9000 and forward to me"
   CLIENT ----"listen 9000"--------> SERVER

3. SERVER opens TCP port 9000 on localhost
   SERVER now listens on 127.0.0.1:9000

4. A process in the container connects to localhost:9000
   PROCESS -----------------------> SERVER:9000

5. SERVER tells CLIENT about new connection
   SERVER ----"connect"------------> CLIENT (via WebSocket)

6. CLIENT connects to local service
   CLIENT -----------------------> localhost:3000

7. Data flows bidirectionally through the tunnel:
   PROCESS <---> SERVER:9000 <==WebSocket==> CLIENT <---> localhost:3000
```

## Installation

```bash
go install github.com/DaniilSokolyuk/vtunnel/cmd/vtunnel@latest
```

## Usage

### Server

Start the vtunnel server, which accepts WebSocket connections from clients and opens TCP listeners on demand.

```bash
# Basic server on port 3001
vtunnel server -port 3001

# With HTTP CONNECT proxy on port 9090 (see section below)
vtunnel server -port 3001 -proxy 9090
```

### Client

Connect to a vtunnel server and forward remote ports to local addresses.

```bash
# Forward remote port 9000 to local service on port 3000
vtunnel client -server ws://tunnel.example.com/ -forward 9000=localhost:3000

# Multiple forwards
vtunnel client -server ws://tunnel.example.com/ \
  -forward 9000=localhost:3000 \
  -forward 9001=localhost:8080

# TLS termination: vtunnel client handles TLS to upstream,
# container accesses the service via plain HTTP on localhost
vtunnel client -server ws://tunnel.example.com/ \
  -forward 8085=tls://www.google.com:443
# curl http://127.0.0.1:8085/ -> 200 OK from google
```

The `-forward` flag format is `remotePort=localAddr`, where:

- `remotePort` is the port the server opens (on 127.0.0.1)
- `localAddr` is the address the client connects to when traffic arrives
- Prefix with `tls://` for client-side TLS termination (the server-side port serves plain TCP)

## HTTP CONNECT Proxy

The server includes an optional HTTP CONNECT proxy that intercepts HTTPS traffic and routes known domains through the tunnel. This is useful when tools inside a container (git, curl, npm) need to reach private services that are only accessible from the client side.

### How It Works

When the server starts with `-proxy 9090`, it runs an HTTP CONNECT proxy on port 9090. The proxy automatically builds a routing table from `Listen` messages received from the client.

When the client calls `Listen(8083, "gitlab.example.com:443")`, the server:
1. Opens TCP port 8083 on localhost (normal tunnel behavior)
2. Registers a proxy mapping: `gitlab.example.com:443` -> `127.0.0.1:8083`

Any process in the container that sets `HTTPS_PROXY=http://localhost:9090` will have its HTTPS `CONNECT` requests checked against this table. Known domains are routed through the local tunnel port, which forwards through the WebSocket back to the client, which connects to the real service. Unknown domains pass through directly to the internet.

### Flow

```
git clone https://gitlab.example.com/repo
  -> HTTPS_PROXY -> CONNECT gitlab.example.com:443
    -> proxy lookup -> 127.0.0.1:8083 (vtunnel)
      -> WebSocket -> client -> gitlab.example.com:443
```

Detailed:

```
Container                          Server                    Client              Private Network
=========                          ======                    ======              ===============

git clone https://gitlab.example.com/repo
  |
  |  CONNECT gitlab.example.com:443
  +---> HTTPS_PROXY (localhost:9090)
          |
          |  lookup: gitlab.example.com:443
          |  found:  127.0.0.1:8083
          |
          +---> 127.0.0.1:8083 (vtunnel listener)
                  |
                  |  tunnel via WebSocket
                  +============================> client
                                                   |
                                                   +---> gitlab.example.com:443
                                                                  |
                                                                  +---> (real server)
```

### Usage in Containers

Inside the container, set the proxy environment variable so that standard tools route HTTPS traffic through the tunnel:

```bash
export HTTPS_PROXY=http://localhost:9090
```

Tools that respect `HTTPS_PROXY` (git, curl, npm, pip, docker, etc.) will automatically send a `CONNECT` request to the proxy. The proxy decides per-domain whether to route through the tunnel or connect directly.

| Domain | Behavior |
|--------|----------|
| Registered via `Listen` | Routed through vtunnel to client |
| Everything else | Direct connection (passthrough) |

## Go Library

vtunnel can be used as a Go library for embedding in your own applications.

### Client

```go
package main

import (
    "log"
    "net/http"
    "os"
    "os/signal"
    "time"

    "github.com/DaniilSokolyuk/vtunnel"
)

func main() {
    // Custom headers for authentication
    headers := http.Header{}
    headers.Set("Authorization", "Bearer token123")

    client := vtunnel.NewClient("wss://tunnel.example.com/",
        vtunnel.WithHeaders(headers),
        vtunnel.WithAutoReconnect(true),
        vtunnel.WithPingInterval(30*time.Second),
        vtunnel.WithReconnectBackoff(1*time.Second, 5*time.Second),
    )

    if err := client.Connect(); err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Remote :8081 -> Local :8081 (LLM proxy)
    client.Listen(8081, "localhost:8081")

    // Remote :8082 -> Local :8082 (MCP server)
    client.Listen(8082, "localhost:8082")

    // Remote :8083 -> gitlab.example.com:443 (private GitLab, TLS terminated by client)
    client.Listen(8083, "gitlab.example.com:443")

    // Wait for interrupt
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    <-c
}
```

### Client Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithPingInterval(d)` | Application-level ping interval. Set to negative to disable. | 30s |
| `WithHeaders(h)` | HTTP headers for the WebSocket handshake. | none |
| `WithAutoReconnect(bool)` | Reconnect automatically after disconnects. Replays all `Listen` calls on reconnect. | false |
| `WithReconnectBackoff(min, max)` | Exponential backoff window for reconnect attempts. | 1s - 5s |

### Server

```go
package main

import (
    "log"
    "net/http"

    "github.com/DaniilSokolyuk/vtunnel"
    "github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
}

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            log.Printf("Upgrade error: %v", err)
            return
        }
        defer conn.Close()

        server := vtunnel.NewServer()
        server.HandleConn(conn)
    })

    log.Println("Tunnel server listening on :3001")
    log.Fatal(http.ListenAndServe(":3001", nil))
}
```

## Protocol

vtunnel uses a JSON-based protocol over WebSocket text frames. Each message is a JSON object with a `type` field.

| Message Type | Direction | Fields | Description |
|-------------|-----------|--------|-------------|
| `listen` | Client -> Server | `port` | Request server to listen on a TCP port |
| `listen_ok` | Server -> Client | `port` | Listener established successfully |
| `listen_err` | Server -> Client | `port`, `error` | Listener failed to start |
| `connect` | Server -> Client | `stream_id`, `port` | New TCP connection accepted on a listened port |
| `data` | Bidirectional | `stream_id`, `data` | Payload bytes for a stream (base64-encoded) |
| `close` | Bidirectional | `stream_id` | Close a stream |
| `ping` | Client -> Server | | Application-level keepalive ping |
| `pong` | Server -> Client | | Application-level keepalive pong |

### Message Format

```json
{
  "type": "data",
  "stream_id": 42,
  "data": "aGVsbG8gd29ybGQ="
}
```

### Keepalive

The client sends `ping` messages at a configurable interval (default 30s). The server responds with `pong`. If no message is received within twice the ping interval, the connection is considered dead. Application-level ping/pong is used instead of WebSocket control frames to work reliably through intermediate proxies.

## Features

- **WebSocket transport** -- works through firewalls and HTTP proxies
- **Multiplexed streams** -- multiple TCP connections over a single WebSocket
- **Keepalive** -- application-level ping/pong to detect dead connections
- **Auto-reconnect** -- exponential backoff reconnect with automatic `Listen` replay
- **TLS termination** -- client-side TLS for `tls://` targets, exposing plain TCP on the server
- **HTTP CONNECT proxy** -- route HTTPS traffic from containers through the tunnel by domain
- **Lightweight** -- minimal dependencies (gorilla/websocket, cenkalti/backoff)

## License

MIT
