# vtunnel

Lightweight reverse tunnel over WebSocket. Expose local services through a remote server.

Uses SSH protocol over WebSocket for multiplexing, encryption, and authentication.

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
+--------------+     SSH over WebSocket
```

## Installation

```bash
go install github.com/DaniilSokolyuk/vtunnel/cmd/vtunnel@latest
```

Or download a binary from [Releases](https://github.com/DaniilSokolyuk/vtunnel/releases).

## Quick Start

### 1. Generate a keypair

```bash
vtunnel keygen
# Private key (client): vt-priv-...
# Public key (server):  vt-pub-...
```

### 2. Start the server

```bash
vtunnel server -port 3001 -client-key "vt-pub-..."
```

### 3. Start the client

```bash
vtunnel client -server ws://tunnel.example.com:3001/ \
  -key "vt-priv-..." \
  -forward 9000=localhost:3000
```

Now any process on the server connecting to `localhost:9000` reaches your local `:3000`.

## Usage

### Server

```bash
vtunnel server [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-port` | WebSocket listen port | `3001` |
| `-proxy` | HTTP CONNECT proxy port (0 = disabled) | `0` |
| `-client-key` | Client public key (`vt-pub-...`). Also `$VTUNNEL_CLIENT_KEY`. | none |

### Client

```bash
vtunnel client [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-server` | WebSocket server URL (required) | — |
| `-key` | Private key (`vt-priv-...`). Also `$VTUNNEL_KEY`. | none |
| `-forward` | Port forward `remotePort=localAddr` (repeatable, at least 1 required) | — |

The `-forward` format is `remotePort=localAddr`:

- `remotePort` — port the server opens on `127.0.0.1`
- `localAddr` — address the client connects to when traffic arrives
- Prefix with `tls://` for client-side TLS termination

```bash
# Single forward
vtunnel client -server ws://tunnel.example.com/ -forward 9000=localhost:3000

# Multiple forwards
vtunnel client -server ws://tunnel.example.com/ \
  -forward 9000=localhost:3000 \
  -forward 9001=localhost:8080

# TLS termination: server exposes plain TCP, client handles TLS
vtunnel client -server ws://tunnel.example.com/ \
  -forward 8085=tls://www.google.com:443
# curl http://127.0.0.1:8085/ -> 200 OK from google
```

### Key Generation

```bash
vtunnel keygen
```

Generates an ed25519 keypair. Give the private key (`vt-priv-...`) to the client and the public key (`vt-pub-...`) to the server.

## Authentication

vtunnel uses SSH public key authentication (ed25519). When both sides are configured with keys:

- The server verifies the client's identity using its public key
- The client verifies the server using a deterministically derived host key (MITM protection)
- No manual host key management needed — both sides compute the host key from the client's public key

Running without keys is possible but insecure — both sides will log a warning.

## HTTP CONNECT Proxy

The server includes an optional HTTP CONNECT proxy that intercepts HTTPS traffic and routes known domains through the tunnel. Useful when tools inside a container (git, curl, npm) need to reach private services that are only accessible from the client side.

### How It Works

When the server starts with `-proxy 9090`, it runs an HTTP CONNECT proxy on port 9090. The proxy automatically builds a routing table from `Listen` messages received from the client.

When the client calls `Listen(8083, "gitlab.example.com:443")`, the server:
1. Opens TCP port 8083 on localhost (normal tunnel behavior)
2. Registers a proxy mapping: `gitlab.example.com:443` -> `127.0.0.1:8083`

Any process that sets `HTTPS_PROXY=http://localhost:9090` will have its HTTPS `CONNECT` requests checked against this table. Known domains go through the tunnel; unknown domains pass through directly to the internet.

### Flow

```
git clone https://gitlab.example.com/repo
  -> HTTPS_PROXY -> CONNECT gitlab.example.com:443
    -> proxy lookup -> 127.0.0.1:8083 (vtunnel)
      -> WebSocket -> client -> gitlab.example.com:443
```

### Usage in Containers

```bash
export HTTPS_PROXY=http://localhost:9090
```

| Domain | Behavior |
|--------|----------|
| Registered via `Listen` | Routed through vtunnel to client |
| Everything else | Direct connection (passthrough) |

## Go Library

vtunnel can be used as a Go library.

### Client

```go
package main

import (
    "log"
    "os"
    "os/signal"
    "time"

    "github.com/DaniilSokolyuk/vtunnel"
)

func main() {
    client := vtunnel.NewClient("wss://tunnel.example.com/",
        vtunnel.WithKey("vt-priv-..."),
        vtunnel.WithKeepAlive(30*time.Second),
        vtunnel.WithReconnectBackoff(1*time.Second, 5*time.Second),
    )

    if err := client.Connect(); err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    client.Listen(8081, "localhost:8081")
    client.Listen(8083, "gitlab.example.com:443")

    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    <-c
}
```

### Client Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithKey(privKey)` | Private key for authentication (`vt-priv-...`). | none |
| `WithKeepAlive(d)` | SSH keepalive ping interval. 0 for default, negative to disable. | 30s |
| `WithHeaders(h)` | HTTP headers for the WebSocket handshake. | none |
| `WithReconnectBackoff(min, max)` | Exponential backoff for reconnect attempts. | 1s–5s |

Reconnection is always enabled. On disconnect, the client reconnects with exponential backoff and replays all `Listen` calls automatically.

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
    server := vtunnel.NewServer(
        vtunnel.WithClientKey("vt-pub-..."),
    )

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            log.Printf("Upgrade error: %v", err)
            return
        }
        defer conn.Close()
        server.HandleConn(conn)
    })

    log.Println("Listening on :3001")
    log.Fatal(http.ListenAndServe(":3001", nil))
}
```

### Server Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithClientKey(pubKey)` | Authorized client public key (`vt-pub-...`). | none |
| `WithServerKeepAlive(d)` | SSH keepalive ping interval. | 30s |

The server also exposes `StartProxy(addr)`, `CloseProxy()`, `SetDomainMapping(domain, target)`, and `RemoveDomainMapping(domain)` for proxy control.

## Protocol

vtunnel runs the SSH protocol over WebSocket binary frames. This gives multiplexed channels, encryption, and authentication out of the box, while remaining compatible with firewalls and HTTP proxies.

**Global requests (client -> server):**

| Request | Payload | Description |
|---------|---------|-------------|
| `listen` | `{"port": N, "local_addr": "..."}` | Open a TCP listener on the server |
| `ping` | — | Keepalive probe (server replies with `pong`) |

**Channels (server -> client):**

| Channel Type | Extra Data | Description |
|--------------|------------|-------------|
| `tunnel` | `{"port": N}` | New TCP connection to forward |

### Keepalive

The client sends SSH `ping` requests at a configurable interval (default 30s). The server responds with `pong`. Application-level keepalive is used instead of WebSocket control frames to work reliably through intermediate proxies.

## Features

- **SSH over WebSocket** — encrypted, multiplexed transport through firewalls and HTTP proxies
- **Key-based authentication** — ed25519 keypair with automatic MITM protection
- **Auto-reconnect** — exponential backoff with automatic `Listen` replay
- **TLS termination** — client-side TLS for `tls://` targets, exposing plain TCP on the server
- **HTTP CONNECT proxy** — route HTTPS traffic from containers through the tunnel by domain
- **Persistent listeners** — server TCP listeners survive client reconnections
- **Lightweight** — minimal dependencies

## License

MIT