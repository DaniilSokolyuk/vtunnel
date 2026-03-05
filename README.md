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
| `-proxy-mitm-ca` | PEM file with CA cert+key for HTTPS MITM interception | none |
| `-client-key` | Client public key (`vt-pub-...`). Also `$VTUNNEL_CLIENT_KEY`. | none |

### Client

```bash
vtunnel client [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-server` | WebSocket server URL (required) | — |
| `-key` | Private key (`vt-priv-...`). Also `$VTUNNEL_KEY`. | none |
| `-forward` | Forward mapping (repeatable, at least 1 required) | — |

The `-forward` flag supports two formats:

**Port-based** (`remotePort=localAddr`) — server opens a TCP port:

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

**Domain-based** (`domain=localAddr`) — proxy routes by hostname, no manual port allocation:

```bash
# Route domain through tunnel to local service
vtunnel client -server ws://tunnel.example.com/ \
  -forward llmproxy.local=localhost:8080

# Multiple domains to the same backend
vtunnel client -server ws://tunnel.example.com/ \
  -forward llmproxy.local=localhost:8080 \
  -forward mcpproxy.local=localhost:8080

# Passthrough: proxy routes through tunnel, client connects to the real host
vtunnel client -server ws://tunnel.example.com/ \
  -forward gitlab.example.com:443=gitlab.example.com:443

# Domain with TLS termination
vtunnel client -server ws://tunnel.example.com/ \
  -forward myalias.local=tls://www.google.com:443
```

Domain forwards require the server to run with `-proxy`. A domain without a port (e.g. `llmproxy.local`) matches both `:80` and `:443`.

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

When the server starts with `-proxy 9090`, it runs an HTTP CONNECT proxy on port 9090. The proxy routes domains registered via `Forward` (or `SetDomainMapping`) through the tunnel. Unknown domains pass through directly to the internet.

When the client calls `Forward("gitlab.example.com:443", "gitlab.example.com:443")`, the server registers the domain in the proxy routing table. Any HTTPS `CONNECT` request for that domain is routed through the tunnel.

### Flow

```
git clone https://gitlab.example.com/repo
  -> HTTPS_PROXY -> CONNECT gitlab.example.com:443
    -> proxy lookup -> vtunnel -> client -> gitlab.example.com:443
```

### HTTPS MITM Interception

By default, the proxy creates a transparent TCP tunnel for HTTPS (CONNECT) — the TLS connection goes end-to-end between the client and the remote server. This works for passthrough where the backend speaks TLS too (e.g. `gitlab.example.com:443=gitlab.example.com:443`), but **fails** when the backend is plain HTTP (e.g. `gitlab.example.com=localhost:8080`) — the client tries TLS, but the backend doesn't speak it.

To intercept HTTPS traffic and route it to plain HTTP backends, provide a CA certificate with `-proxy-mitm-ca`:

```bash
vtunnel server -port 3001 -proxy 9090 -proxy-mitm-ca ca.pem
```

The proxy will terminate TLS for mapped domains, generate certificates on the fly signed by the provided CA, and forward decrypted requests to the backend as plain HTTP. Clients must trust the CA certificate for HTTPS to work without errors.

The PEM file should contain both the CA certificate and private key.

### Usage in Containers

```bash
export HTTPS_PROXY=http://localhost:9090
```

| Domain | Behavior |
|--------|----------|
| Registered via `Forward` | Routed through vtunnel to client |
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
    client.Forward("gitlab.example.com:443", "gitlab.example.com:443")
    client.Forward("llmproxy.local", "localhost:8082")

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

Reconnection is always enabled. On disconnect, the client reconnects with exponential backoff and replays all `Listen` and `Forward` calls automatically.

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
| `WithProxyMitmCA(cert)` | CA certificate for HTTPS MITM interception. | none |

The server also exposes `StartProxy(addr)`, `CloseProxy()`, `SetDomainMapping(domain, target)`, and `RemoveDomainMapping(domain)` for proxy control.

## Protocol

vtunnel runs the SSH protocol over WebSocket binary frames. This gives multiplexed channels, encryption, and authentication out of the box, while remaining compatible with firewalls and HTTP proxies.

**Global requests (client -> server):**

| Request | Payload | Description |
|---------|---------|-------------|
| `listen` | `{"port": N, "local_addr": "...", "domain": "..."}` | Open a TCP listener on the server. Optional `domain` registers a proxy mapping. Port 0 = auto-allocate. |
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
- **Domain forwarding** — route by hostname through the proxy, no manual port allocation
- **Auto-reconnect** — exponential backoff with automatic `Listen`/`Forward` replay
- **TLS termination** — client-side TLS for `tls://` targets, exposing plain TCP on the server
- **HTTP CONNECT proxy** — route HTTPS traffic from containers through the tunnel by domain
- **Persistent listeners** — server TCP listeners survive client reconnections
- **Lightweight** — minimal dependencies

## License

MIT