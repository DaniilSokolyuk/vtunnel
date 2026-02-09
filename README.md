# vtunnel

A lightweight reverse tunnel over WebSocket. Expose local services through a remote server.

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
                      |                 |           │                     |
+--------------+      |                 +-----------│---------------------+
| vtunnel      |      |                             │
| CLIENT       |------+                             │
|              |<===================================┘
+--------------+        WebSocket tunnel


Proxy options (expose localhost ports to internet):
  • nginx        - proxy_pass http://localhost:9000
  • Caddy        - reverse_proxy localhost:9000
  • Cloudflare   - cloudflare containers/sandboxes/cloudflared
  • HAProxy      - server backend localhost:9000
  • SSH          - ssh -R 80:localhost:9000 server

Example flow:
  User request ──> proxy:443 ──> vtunnel:9000 ══tunnel══> client ──> localhost:3000
```

**Step by step:**

```
1. CLIENT connects to SERVER via WebSocket
   CLIENT =========================> SERVER (ws://95.100.200.50/tunnel)

2. CLIENT says: "Please open port 9000 and forward to me"
   CLIENT ----"listen 9000"--------> SERVER

3. SERVER opens TCP port 9000
   SERVER now listens on 95.100.200.50:9000

4. USER connects to server's public port
   USER -----------------------> SERVER:9000

5. SERVER tells CLIENT about new connection
   SERVER ----"new connection"----> CLIENT (via WebSocket)

6. CLIENT connects to local app
   CLIENT -----------------------> localhost:3000

7. Data flows through the tunnel:
   USER <---> SERVER:9000 <==WebSocket==> CLIENT <---> localhost:3000
```

**Simple example:**

```
Port mapping: SERVER:9000 --> CLIENT:localhost:3000

User visits:     http://95.100.200.50:9000/hello
                            |
                            v (through tunnel)
Actually hits:   http://localhost:3000/hello (on your machine!)
```

## Installation

```bash
go install github.com/DaniilSokolyuk/vtunnel/cmd/vtunnel@latest
```

## Usage

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
    http.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            log.Printf("Upgrade error: %v", err)
            return
        }
        defer conn.Close()

        server := vtunnel.NewServer()
        server.HandleConn(conn)
    })

    log.Println("Tunnel server listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

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
    // Connect to tunnel server
    client := vtunnel.NewClient("wss://tunnel.example.com/tunnel",
        vtunnel.WithPingInterval(30*time.Second),
    )

    if err := client.Connect(); err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Expose local services through remote ports
    // Remote :9000 -> Local :3000
    client.Listen(9000, "localhost:3000")

    // Remote :9001 -> Local :8080
    client.Listen(9001, "localhost:8080")

    // Wait for interrupt
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt)
    <-c
}
```

## Client Options

```go
// Default ping interval (30s)
client := vtunnel.NewClient("ws://server/tunnel")

// Custom ping interval
client := vtunnel.NewClient("ws://server/tunnel",
    vtunnel.WithPingInterval(10*time.Second),
)

// Disable ping (not recommended for production)
client := vtunnel.NewClient("ws://server/tunnel",
    vtunnel.WithPingInterval(-1),
)

// With custom headers (e.g., authentication)
headers := http.Header{}
headers.Set("Authorization", "Bearer token123")
client := vtunnel.NewClient("ws://server/tunnel",
    vtunnel.WithHeaders(headers),
)
```

## Example: Expose Local Web Server

**Scenario:** You have a web server running on `localhost:3000` and want to make it accessible at `tunnel.example.com:9000`.

```go
client := vtunnel.NewClient("wss://tunnel.example.com/tunnel")
client.Connect()
client.Listen(9000, "localhost:3000")
```

Now `http://tunnel.example.com:9000` forwards to your local `localhost:3000`.

## Example: Multiple Services

```go
client := vtunnel.NewClient("wss://tunnel.example.com/tunnel")
client.Connect()

// Web app
client.Listen(9000, "localhost:3000")

// API server
client.Listen(9001, "localhost:8080")

// Database (be careful with security!)
client.Listen(9002, "localhost:5432")
```

## Features

- **WebSocket transport** - Works through firewalls and proxies
- **Multiplexed streams** - Multiple connections over single WebSocket
- **Keepalive** - Automatic ping/pong to maintain connection through Cloudflare etc.
- **Lightweight** - Minimal dependencies (only gorilla/websocket)

## Protocol

The tunnel uses a simple JSON-based protocol over WebSocket:

| Message Type | Direction | Description |
|-------------|-----------|-------------|
| `listen` | Client -> Server | Request server to listen on a port |
| `connect` | Server -> Client | New TCP connection received |
| `data` | Bidirectional | Stream data |
| `close` | Bidirectional | Close a stream |

## License

MIT
