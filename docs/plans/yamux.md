# Migration: SSH -> yamux + custom auth

## Context

SSH (`golang.org/x/crypto/ssh`) is the performance bottleneck in vtunnel. SSH adds per-packet encryption, MAC computation, and framing overhead unnecessary for this use case — vtunnel runs over WebSocket which can already be secured via TLS (`wss://`). The project only needs: stream multiplexing, keepalive, and simple auth.

Replacing SSH with `hashicorp/yamux` for stream multiplexing and a lightweight custom ed25519 challenge-response handshake will significantly reduce per-byte CPU overhead and improve throughput.

**Breaking wire protocol change.** Matched client/server pairs required after migration. Key format (`vt-priv-`/`vt-pub-`) and public Go API preserved — existing keys and deployment configs continue to work.

---

## 1. Architecture Overview

```
BEFORE (current):
  WebSocket -> wsConn (net.Conn) -> SSH protocol (crypto, auth, mux) -> SSH channels

AFTER:
  WebSocket -> wsConn (net.Conn) -> Custom handshake (auth) -> yamux session (mux) -> yamux streams
```

### What yamux replaces
| SSH feature | yamux replacement |
|---|---|
| Stream multiplexing (SSH channels) | yamux streams |
| Keepalive (SSH ping/pong global requests) | yamux built-in keepalive |
| Encryption | Not needed (use `wss://` for TLS) |
| Auth (public key challenge-response) | Custom ed25519 handshake (Section 2) |
| Global requests (`"listen"`, `"ping"`) | Control stream protocol (Section 3) |
| `sshConn.Wait()` (death detection) | `<-session.CloseChan()` |
| `sshConn.OpenChannel()` | `session.Open()` |
| Channel accept/reject | `session.AcceptStream()` |

---

## 2. Custom Auth Handshake Protocol

Runs on raw `net.Conn` (the `wsConn`) **before** yamux session creation. Rejects unauthorized connections before allocating any session resources.

### Wire format

Each message: `[4 bytes big-endian uint32: payload length][JSON payload]`

### Authenticated flow (3 messages)

```
Client connects via WebSocket
         |
Server -> Client:  AuthChallenge
  {
    "challenge": "<base64, 32 random bytes>",
    "server_pub_hash": "<base64, SHA256(client_public_key_bytes)>"
  }
         |
Client: verifies server_pub_hash == SHA256(own_public_key_bytes)
        (MITM protection: if mismatch -> close connection)
Client: signs raw challenge bytes with ed25519 private key
         |
Client -> Server:  AuthResponse
  {
    "signature": "<base64, ed25519.Sign(privkey, challenge_bytes)>",
    "client_pub": "<base64, ed25519 public key, 32 bytes>"
  }
         |
Server: compares client_pub to expected client public key (byte equality)
Server: verifies ed25519.Verify(client_pub, challenge_bytes, signature)
         |
Server -> Client:  AuthResult
  {"ok": true}
  or
  {"ok": false, "error": "unauthorized key"}
         |
Both sides proceed to create yamux session
```

### MITM protection

The `server_pub_hash` field is `SHA256(client_public_key_bytes)` — the same value both sides can compute independently from the client's public key. This replaces SSH's deterministic host key derivation (`deriveHostKey`). The client verifies the server knows the correct public key before revealing its signature.

### No-auth flow

```
Server -> Client:  {"challenge": "", "server_pub_hash": ""}
Client -> Server:  {"signature": "", "client_pub": ""}
Server -> Client:  {"ok": true}
```

Both sides log `WARNING: Authentication is DISABLED`.

### Timeout

30-second deadline on the entire handshake (same as current SSH handshake timeout).

### Handshake types

```go
type authChallenge struct {
    Challenge     string `json:"challenge"`       // base64, 32 random bytes
    ServerPubHash string `json:"server_pub_hash"` // base64, SHA256(client_pubkey_bytes)
}

type authResponse struct {
    Signature string `json:"signature"`  // base64, ed25519 signature over raw challenge
    ClientPub string `json:"client_pub"` // base64, ed25519 public key (32 bytes)
}

type authResult struct {
    OK    bool   `json:"ok"`
    Error string `json:"error,omitempty"`
}
```

### Handshake functions

```go
// Server side: send challenge, verify response, send result.
// clientPubKey is nil for no-auth mode.
func serverHandshake(conn net.Conn, clientPubKey ed25519.PublicKey) error

// Client side: receive challenge, verify server identity, sign, send response, read result.
// privKey is nil for no-auth mode.
func clientHandshake(conn net.Conn, privKey ed25519.PrivateKey) error
```

---

## 3. Control Stream Protocol

After yamux session is created, the **client** immediately opens the first stream = **control stream**. This replaces SSH global requests (`"listen"`, `"ping"`).

### Wire format

Same as handshake: `[4 bytes big-endian uint32: length][JSON payload]`

### Message types

```go
type controlRequest struct {
    ID   uint32 `json:"id"`
    Type string `json:"type"` // "listen"
    listenRequest              // embedded: Port, LocalAddr, Domain
}

type controlResponse struct {
    ID    uint32 `json:"id"`
    OK    bool   `json:"ok"`
    Error string `json:"error,omitempty"`
    listenRequest               // embedded: reply payload (Port, LocalAddr)
}
```

### Request-reply flow

1. Client assigns incrementing uint32 ID via `atomic.Uint32`
2. Client writes `controlRequest` to control stream
3. Server reads request, processes it, writes `controlResponse` with same ID
4. Client has a reader goroutine that dispatches responses to `map[uint32]chan controlResponse` by ID

### Listen request example

```
Client -> Server:  {"id":1, "type":"listen", "port":8080, "local_addr":"localhost:3000"}
Server -> Client:  {"id":1, "ok":true, "port":8080}

Client -> Server:  {"id":2, "type":"listen", "port":0, "local_addr":"localhost:8080", "domain":"app.test"}
Server -> Client:  {"id":2, "ok":true, "port":54321}
```

### Why control stream, not per-request streams

- SSH used global requests (session-level). One persistent control stream is the closest analog.
- Avoids stream open/close overhead per control message.
- Clean separation: control stream always the first accepted stream on server side.

---

## 4. Tunnel Stream Protocol

All yamux streams **other than the control stream** carry tunnel data.

### Flow

1. Server accepts a TCP connection on a tunnel port
2. Server calls `session.Open()` to create a new yamux stream
3. Server writes a tunnel header: `writeMsg(stream, tunnelRequest{Port: N})`
4. Client reads header via `readMsg(stream, &req)`, looks up forward by port
5. Client dials local target (with optional `tls://` prefix for TLS termination)
6. Bidirectional pipe: `pipe(stream, localConn)`

### Stream disambiguation

No ambiguity between control and tunnel streams:
- **Client opens**: control stream (first and only `session.Open()`)
- **Server opens**: tunnel streams (`session.Open()` per TCP connection)
- **Server accepts**: control stream (first `session.AcceptStream()`)
- **Client accepts**: tunnel streams (`session.AcceptStream()` in loop)

---

## 5. Yamux Configuration

```go
cfg := yamux.DefaultConfig()
cfg.MaxStreamWindowSize = 16 * 1024 * 1024  // 16 MB (default 256 KB is too small for high-throughput tunnels)
cfg.EnableKeepAlive = true
cfg.KeepAliveInterval = keepAlive            // default 30s, configurable via WithKeepAlive/WithServerKeepAlive
cfg.ConnectionWriteTimeout = 10 * time.Second
cfg.StreamOpenTimeout = 10 * time.Second
cfg.LogOutput = io.Discard
```

- Negative `keepAlive` value -> `cfg.EnableKeepAlive = false`
- `MaxStreamWindowSize = 16 MB` — critical for throughput. The default 256 KB window causes frequent stalls on high-bandwidth links. 16 MB allows streams to sustain high throughput without waiting for window updates.

---

## 6. File-by-File Changes

### 6.1 `go.mod`

```diff
+require github.com/hashicorp/yamux v0.1.2
-require golang.org/x/crypto v0.48.0
```

Keep: `gorilla/websocket`, `cenkalti/backoff/v4`, `golang.org/x/net` (used by proxy for http2/h2c).

### 6.2 `auth.go` — Rewrite

**Remove all `ssh.*` imports and types.**

**Keep unchanged:**
- `GenerateKeyPair()` — key format and encoding are independent of SSH
- Key prefix constants (`vt-priv-`, `vt-pub-`)

**Change return types:**

```go
// BEFORE:
func parsePrivateKey(encoded string) (ssh.Signer, error)
func parsePublicKey(encoded string) (ssh.PublicKey, error)
func deriveHostKey(clientPubKey ssh.PublicKey) (ssh.Signer, error)

// AFTER:
func parsePrivateKey(encoded string) (ed25519.PrivateKey, error)
func parsePublicKey(encoded string) (ed25519.PublicKey, error)
func deriveServerIdentity(clientPubKey ed25519.PublicKey) []byte  // returns SHA256(pubkey_bytes)
```

**Add:**
- Handshake types: `authChallenge`, `authResponse`, `authResult` (see Section 2)
- `serverHandshake(conn net.Conn, clientPubKey ed25519.PublicKey) error`
- `clientHandshake(conn net.Conn, privKey ed25519.PrivateKey) error`

**`deriveServerIdentity` change:**
```go
// BEFORE: SHA256(ssh_pubkey.Marshal()) -> ed25519 seed -> ssh.Signer
// AFTER:  SHA256(raw_ed25519_pubkey_bytes) -> []byte (hash used directly for comparison)
```

The previous implementation marshalled the key via `ssh.PublicKey.Marshal()` which includes SSH wire format headers. The new implementation hashes the raw 32-byte ed25519 public key directly. **This means existing keys produce different identity hashes** — acceptable because the wire protocol is breaking anyway.

### 6.3 `wsconn.go` — Moderate changes

**Keep unchanged:**
- `wsConn` struct + `Read`/`Write`/`SetDeadline` methods
- `NewWSConn()` function
- `pipe()` function
- `setTCPOptions()` function
- `listenRequest` struct
- `tunnelRequest` struct
- `marshalJSON()` helper

**Remove:**
- `keepAliveLoop()` — yamux has built-in keepalive
- `handleRequests()` — SSH ping handler, no longer needed
- `rejectChannels()` — SSH-specific
- `generateHostKey()` — ephemeral SSH ECDSA host key, no longer needed

**Add:**
```go
// Length-prefixed JSON wire helpers
func writeMsg(w io.Writer, v any) error     // write [4-byte len][JSON]
func readMsg(r io.Reader, v any) error       // read [4-byte len][JSON], with max size guard

// Control stream message types
type controlRequest struct {
    ID   uint32 `json:"id"`
    Type string `json:"type"`
    listenRequest
}

type controlResponse struct {
    ID    uint32 `json:"id"`
    OK    bool   `json:"ok"`
    Error string `json:"error,omitempty"`
    listenRequest
}
```

### 6.4 `server.go` — Major rewrite

**Struct changes:**
```go
type Server struct {
    // REMOVED:
    //   sshConfig    *ssh.ServerConfig
    //   clientPubKey ssh.PublicKey
    //   activeConn   ssh.Conn

    // CHANGED:
    clientPubKey  ed25519.PublicKey  // nil = no auth
    activeSession *yamux.Session

    // UNCHANGED:
    keepAlive     time.Duration
    activeConnMu  sync.RWMutex
    connReady     chan struct{}
    listeners     map[int]net.Listener
    listenersMu   sync.Mutex
    domainMap     map[string]string
    domainMu      sync.RWMutex
    proxyListener net.Listener
    proxyDone     chan struct{}
    proxyOnce     sync.Once
    mitmCA        *tls.Certificate
    tlsUpstream   map[string]string
    tlsUpstreamMu sync.RWMutex
}
```

**`NewServer()` rewrite:**
```go
func NewServer(opts ...ServerOption) *Server {
    s := &Server{
        keepAlive:   defaultKeepAlive,
        connReady:   make(chan struct{}),
        listeners:   make(map[int]net.Listener),
        domainMap:   make(map[string]string),
        tlsUpstream: make(map[string]string),
    }
    for _, opt := range opts {
        opt(s)
    }
    if s.clientPubKey == nil {
        log.Println("[vtunnel-server] WARNING: No client key configured. Authentication is DISABLED.")
    }
    return s
}
```

No more SSH config, host key generation, or `PublicKeyCallback` setup.

**`HandleConn()` rewrite:**
```go
func (s *Server) HandleConn(wsConn *websocket.Conn) {
    conn := NewWSConn(wsConn)
    conn.SetDeadline(time.Now().Add(30 * time.Second))

    // 1. Custom auth handshake
    if err := serverHandshake(conn, s.clientPubKey); err != nil {
        log.Printf("[vtunnel-server] Handshake failed: %v", err)
        return
    }
    conn.SetDeadline(time.Time{})

    // 2. Create yamux server session
    cfg := s.yamuxConfig()
    session, err := yamux.Server(conn, cfg)
    if err != nil {
        log.Printf("[vtunnel-server] yamux session failed: %v", err)
        return
    }
    defer session.Close()

    log.Println("[vtunnel-server] Client connected")
    s.setSession(session)
    defer func() {
        s.clearSession(session)
        log.Println("[vtunnel-server] Client disconnected")
    }()

    // 3. Accept control stream (first stream from client)
    ctrlStream, err := session.AcceptStream()
    if err != nil {
        log.Printf("[vtunnel-server] Accept control stream failed: %v", err)
        return
    }
    go s.handleControlStream(ctrlStream)

    // 4. Block until session dies
    <-session.CloseChan()
}
```

**`yamuxConfig()` helper:**
```go
func (s *Server) yamuxConfig() *yamux.Config {
    cfg := yamux.DefaultConfig()
    cfg.MaxStreamWindowSize = 16 * 1024 * 1024
    cfg.ConnectionWriteTimeout = 10 * time.Second
    cfg.StreamOpenTimeout = 10 * time.Second
    cfg.LogOutput = io.Discard
    if s.keepAlive > 0 {
        cfg.EnableKeepAlive = true
        cfg.KeepAliveInterval = s.keepAlive
    } else {
        cfg.EnableKeepAlive = false
    }
    return cfg
}
```

**`handleControlStream()` — new, replaces `handleRequests()`:**
```go
func (s *Server) handleControlStream(stream *yamux.Stream) {
    defer stream.Close()
    for {
        var req controlRequest
        if err := readMsg(stream, &req); err != nil {
            return // stream/session closed
        }
        switch req.Type {
        case "listen":
            reply, err := s.handleListen(req.listenRequest)
            resp := controlResponse{ID: req.ID, OK: err == nil, listenRequest: reply}
            if err != nil {
                resp.Error = err.Error()
            }
            if err := writeMsg(stream, resp); err != nil {
                return
            }
        default:
            writeMsg(stream, controlResponse{ID: req.ID, OK: false, Error: "unknown request type"})
        }
    }
}
```

**`handleListen()` signature change:**
```go
// BEFORE:
func (s *Server) handleListen(_ ssh.Conn, r *ssh.Request)

// AFTER:
func (s *Server) handleListen(req listenRequest) (listenRequest, error)
```

Returns the reply payload instead of calling `r.Reply()`. Internal logic (listener creation, domain mapping, accept loop spawn) unchanged.

**`handleTunnelConn()` rewrite:**
```go
func (s *Server) handleTunnelConn(tcpConn net.Conn, port int) {
    defer tcpConn.Close()

    session := s.getSession()
    if session == nil {
        log.Printf("[vtunnel-server] No session for port %d (timeout)", port)
        return
    }

    stream, err := session.Open()
    if err != nil {
        log.Printf("[vtunnel-server] Open stream failed for port %d: %v", port, err)
        return
    }
    defer stream.Close()

    // Write tunnel header
    if err := writeMsg(stream, tunnelRequest{Port: port}); err != nil {
        log.Printf("[vtunnel-server] Write tunnel header failed: %v", err)
        return
    }

    log.Printf("[vtunnel-server] New tunnel: port=%d", port)
    pipe(stream, tcpConn)
}
```

**Renames:**
- `setSSH(conn ssh.Conn)` -> `setSession(session *yamux.Session)`
- `clearSSH(conn ssh.Conn)` -> `clearSession(session *yamux.Session)`
- `getSSH() ssh.Conn` -> `getSession() *yamux.Session`

Logic unchanged (connReady channel pattern, RWMutex, timeout wait).

### 6.5 `client.go` — Major rewrite

**Struct changes:**
```go
type Client struct {
    // REMOVED:
    //   sshConn    ssh.Conn
    //   authSigner ssh.Signer

    // CHANGED/ADDED:
    session    *yamux.Session
    privKey    ed25519.PrivateKey      // nil = no auth

    // Control stream state:
    ctrlStream *yamux.Stream
    ctrlMu     sync.Mutex              // serialize writes to control stream
    pending    map[uint32]chan controlResponse
    pendingMu  sync.Mutex
    nextID     atomic.Uint32

    // UNCHANGED:
    wsURL          string
    headers        http.Header
    connMu         sync.RWMutex
    forwards       map[int]string
    mu             sync.RWMutex
    done           chan struct{}
    closeOnce      sync.Once
    ctx            context.Context
    cancel         context.CancelFunc
    keepAlive      time.Duration
    reconnectMin   time.Duration
    reconnectMax   time.Duration
    domainForwards map[string]string
}
```

**`WithKey()` change:**
```go
// BEFORE:
func WithKey(privKey string) Option {
    return func(c *Client) {
        signer, err := parsePrivateKey(privKey)  // returns ssh.Signer
        c.authSigner = signer
    }
}

// AFTER:
func WithKey(privKey string) Option {
    return func(c *Client) {
        key, err := parsePrivateKey(privKey)  // returns ed25519.PrivateKey
        c.privKey = key
    }
}
```

**`dialOnce()` rewrite:**
```go
func (c *Client) dialOnce() (*yamux.Session, error) {
    // 1. WebSocket dial (unchanged)
    dialer := websocket.Dialer{HandshakeTimeout: defaultHandshakeTimeout}
    wsConn, _, err := dialer.DialContext(c.ctx, c.wsURL, c.headers)
    if err != nil {
        return nil, err
    }
    conn := NewWSConn(wsConn)

    // 2. Custom auth handshake
    conn.SetDeadline(time.Now().Add(defaultHandshakeTimeout))
    if err := clientHandshake(conn, c.privKey); err != nil {
        wsConn.Close()
        return nil, fmt.Errorf("handshake: %w", err)
    }
    conn.SetDeadline(time.Time{})

    // 3. Create yamux client session
    cfg := c.yamuxConfig()
    session, err := yamux.Client(conn, cfg)
    if err != nil {
        wsConn.Close()
        return nil, fmt.Errorf("yamux session: %w", err)
    }

    // 4. Open control stream (first stream)
    ctrlStream, err := session.Open()
    if err != nil {
        session.Close()
        return nil, fmt.Errorf("open control stream: %w", err)
    }
    c.ctrlStream = ctrlStream
    c.pending = make(map[uint32]chan controlResponse)

    // 5. Start background goroutines
    go c.readControlResponses(ctrlStream)
    go c.acceptTunnelStreams(session)

    return session, nil
}
```

**`yamuxConfig()` helper:**
```go
func (c *Client) yamuxConfig() *yamux.Config {
    cfg := yamux.DefaultConfig()
    cfg.MaxStreamWindowSize = 16 * 1024 * 1024
    cfg.ConnectionWriteTimeout = 10 * time.Second
    cfg.StreamOpenTimeout = 10 * time.Second
    cfg.LogOutput = io.Discard
    if c.keepAlive > 0 {
        cfg.EnableKeepAlive = true
        cfg.KeepAliveInterval = c.keepAlive
    } else {
        cfg.EnableKeepAlive = false
    }
    return cfg
}
```

**`readControlResponses()` — new:**
```go
func (c *Client) readControlResponses(stream *yamux.Stream) {
    for {
        var resp controlResponse
        if err := readMsg(stream, &resp); err != nil {
            // Session dying, clean up all pending
            c.pendingMu.Lock()
            for id, ch := range c.pending {
                close(ch)
                delete(c.pending, id)
            }
            c.pendingMu.Unlock()
            return
        }
        c.pendingMu.Lock()
        if ch, ok := c.pending[resp.ID]; ok {
            ch <- resp
            delete(c.pending, resp.ID)
        }
        c.pendingMu.Unlock()
    }
}
```

**`sendControl()` — new, replaces `sshConn.SendRequest()`:**
```go
func (c *Client) sendControl(req controlRequest) (controlResponse, error) {
    id := c.nextID.Add(1)
    req.ID = id

    ch := make(chan controlResponse, 1)
    c.pendingMu.Lock()
    c.pending[id] = ch
    c.pendingMu.Unlock()

    c.ctrlMu.Lock()
    err := writeMsg(c.ctrlStream, req)
    c.ctrlMu.Unlock()
    if err != nil {
        c.pendingMu.Lock()
        delete(c.pending, id)
        c.pendingMu.Unlock()
        return controlResponse{}, err
    }

    select {
    case resp, ok := <-ch:
        if !ok {
            return controlResponse{}, fmt.Errorf("connection closed")
        }
        return resp, nil
    case <-c.ctx.Done():
        c.pendingMu.Lock()
        delete(c.pending, id)
        c.pendingMu.Unlock()
        return controlResponse{}, c.ctx.Err()
    }
}
```

**`sendListen()` rewrite:**
```go
func (c *Client) sendListen(session *yamux.Session, port int, localAddr string) error {
    resp, err := c.sendControl(controlRequest{
        Type:          "listen",
        listenRequest: listenRequest{Port: port, LocalAddr: localAddr},
    })
    if err != nil {
        return fmt.Errorf("listen request: %w", err)
    }
    if !resp.OK {
        return fmt.Errorf("listen rejected: %s", resp.Error)
    }
    log.Printf("[vtunnel-client] Listen OK: port=%d", port)
    return nil
}
```

**`sendListenWithDomain()` — same pattern, parses `resp.Port` for domain forwards.**

**`acceptTunnelStreams()` — replaces `handleChannels()`:**
```go
func (c *Client) acceptTunnelStreams(session *yamux.Session) {
    for {
        stream, err := session.AcceptStream()
        if err != nil {
            return // session closed
        }
        go c.handleTunnel(stream)
    }
}
```

**`handleTunnel()` rewrite:**
```go
func (c *Client) handleTunnel(stream *yamux.Stream) {
    defer stream.Close()

    var req tunnelRequest
    if err := readMsg(stream, &req); err != nil {
        log.Printf("[vtunnel-client] Read tunnel header failed: %v", err)
        return
    }

    c.mu.RLock()
    localAddr, ok := c.forwards[req.Port]
    c.mu.RUnlock()
    if !ok {
        log.Printf("[vtunnel-client] No forward for port %d", req.Port)
        return
    }

    localConn, err := c.dialTarget(localAddr)
    if err != nil {
        log.Printf("[vtunnel-client] Failed to connect to %s: %v", localAddr, err)
        return
    }

    log.Printf("[vtunnel-client] New tunnel: port=%d -> %s", req.Port, localAddr)
    pipe(stream, localConn)
}
```

No more `ch.Accept()`/`ch.Reject()` dance — stream is already open.

**`connectionLoop()` change:**
```go
// BEFORE:
if conn := c.getSSH(); conn != nil {
    conn.Wait()
}

// AFTER:
if session := c.getSession(); session != nil {
    <-session.CloseChan()
}
```

**`setSSH`/`getSSH` -> `setSession`/`getSession` (type `*yamux.Session`).**

**`Close()`:**
```go
func (c *Client) Close() error {
    c.closeOnce.Do(func() {
        c.cancel()
        close(c.done)
    })
    session := c.getSession()
    if session != nil {
        session.Close()
        c.setSession(nil)
    }
    return nil
}
```

### 6.6 `proxy.go` — No changes

Zero SSH imports. Interacts with Server only through `resolveDomain()`, `tlsUpstreamHost()`, `SetDomainMapping()`.

### 6.7 `mitm.go` — No changes

Certificate cache, no SSH usage.

### 6.8 `cmd/vtunnel/main.go` — No changes

Uses only public API (`NewServer`, `NewClient`, `WithClientKey`, `WithKey`, `HandleConn`, etc.).

### 6.9 `cmd/bench/main.go` — No changes

Uses only public API.

---

## 7. Implementation Order

| Step | File | Description |
|------|------|-------------|
| 1 | `go.mod` | `go get github.com/hashicorp/yamux` |
| 2 | `auth.go` | Rewrite: remove ssh types, return raw ed25519 types. Add `deriveServerIdentity()`. Add handshake types + `serverHandshake()`/`clientHandshake()`. Add `writeMsg()`/`readMsg()` wire helpers. |
| 3 | `wsconn.go` | Remove: `keepAliveLoop`, `handleRequests`, `rejectChannels`, `generateHostKey`. Add: control message types (`controlRequest`, `controlResponse`). |
| 4 | `server.go` | Rewrite: yamux session, custom handshake, control stream handler, tunnel stream open. Rename setSSH/getSSH/clearSSH. |
| 5 | `client.go` | Rewrite: yamux session, custom handshake, control stream send/receive, tunnel stream accept. Add sendControl() + pending map. |
| 6 | `vtunnel_auth_test.go` | Rewrite `TestAuthWrongPrivateKeyKnownPublic` to use custom handshake instead of raw SSH `NewClientConn`. |
| 7 | `go.mod` | `go mod tidy` — removes `golang.org/x/crypto` |

---

## 8. Test Strategy

### Tests requiring NO changes (use only public API):

All these tests call `NewClient`, `NewServer`, `Connect`, `Listen`, `Forward`, `HandleConn` — the public API is unchanged:

- `vtunnel_test.go` — `TestBasicTunnel`, `TestMultiplePorts`, `TestMultipleConnections`, `TestLargePayload`, `TestTCPStream`, `TestKeepAlive`, `TestHandleConnReplace`, `TestTLSTermination`
- `vtunnel_reconnect_test.go` — all 9 tests including `TestKeepAliveDetectsSilentDrop`
- `vtunnel_forward_test.go` — all 6 tests including `TestDomainForwardSameDomainTargetWithMitm`
- `proxy_test.go` — all tests (HTTP/1.1, HTTP/2, CONNECT, MITM)
- `proxy_regression_test.go` — TE trailers, IP literal, TLS fallback
- `proxy_git_test.go` — git clone via HTTP and HTTPS+MITM
- `proxy_grpcurl_test.go` — grpcurl via MITM tunnel
- `proxy_mitm_fallback_test.go` — H2→H1.1 fallback
- `testca_test.go` — CA generation helper

### Tests requiring changes:

- `vtunnel_auth_test.go`:
  - `TestAuthWrongPrivateKeyKnownPublic` — **must rewrite**. Currently constructs raw `ssh.NewClientConn` with attacker's key. New version: open WebSocket, perform custom handshake manually with wrong private key, verify handshake fails with auth error (not MITM detection).
  - All other auth tests (`TestAuthKeyPairGeneration`, `TestAuthValidKey`, `TestAuthWrongKey`, `TestAuthNoKeyOnClient`, `TestAuthNoKeyOnServer`, `TestAuthReconnectWithKey`) — unchanged, use public API only.

### New tests to add:

- `writeMsg`/`readMsg` round-trip unit test
- `serverHandshake`/`clientHandshake` unit tests:
  - Matching keys -> success
  - Wrong key -> auth failure
  - MITM (wrong `server_pub_hash`) -> client-side rejection
  - No-auth mode -> success with empty fields
  - Timeout (stalled peer) -> deadline error

### Performance verification:

```bash
# Before migration (on current SSH code):
go run ./cmd/bench/ -size 1GB -c 4 -mode all > bench_ssh.txt

# After migration:
go run ./cmd/bench/ -size 1GB -c 4 -mode all > bench_yamux.txt

# Compare throughput numbers
diff bench_ssh.txt bench_yamux.txt
```

---

## 10. Tasks

### Task 1: Add yamux dependency and wire protocol helpers
- [x] Add `github.com/hashicorp/yamux` to go.mod
- [x] Add `writeMsg()`/`readMsg()` length-prefixed JSON wire helpers to wsconn.go
- [x] Add control stream message types (`controlRequest`, `controlResponse`) to wsconn.go
- [x] Add unit tests for `writeMsg`/`readMsg` round-trip

### Task 2: Rewrite auth.go — remove SSH types, add custom handshake
- [ ] Change `parsePrivateKey` to return `ed25519.PrivateKey`
- [ ] Change `parsePublicKey` to return `ed25519.PublicKey`
- [ ] Replace `deriveHostKey` with `deriveServerIdentity` returning `[]byte` (SHA256 hash)
- [ ] Remove all `golang.org/x/crypto/ssh` imports from auth.go
- [ ] Add handshake types: `authChallenge`, `authResponse`, `authResult`
- [ ] Implement `serverHandshake(conn net.Conn, clientPubKey ed25519.PublicKey) error`
- [ ] Implement `clientHandshake(conn net.Conn, privKey ed25519.PrivateKey) error`
- [ ] Add handshake unit tests (matching keys, wrong key, MITM detection, no-auth, timeout)

### Task 3: Rewrite server.go — yamux session, control stream, tunnel streams
- [ ] Change Server struct: replace `ssh.Conn`/`ssh.ServerConfig` with `*yamux.Session`/`ed25519.PublicKey`
- [ ] Rewrite `NewServer()` — remove SSH config setup
- [ ] Rewrite `HandleConn()` — custom handshake + yamux server session + control stream accept
- [ ] Add `yamuxConfig()` helper
- [ ] Implement `handleControlStream()` replacing SSH `handleRequests()`
- [ ] Refactor `handleListen()` to return `(listenRequest, error)` instead of using `ssh.Request.Reply()`
- [ ] Rewrite `handleTunnelConn()` — use `session.Open()` + `writeMsg` tunnel header
- [ ] Rename `setSSH`/`clearSSH`/`getSSH` to `setSession`/`clearSession`/`getSession`
- [ ] Remove all `golang.org/x/crypto/ssh` imports from server.go

### Task 4: Rewrite client.go — yamux session, control stream, tunnel accept
- [ ] Change Client struct: replace `ssh.Conn`/`ssh.Signer` with `*yamux.Session`/`ed25519.PrivateKey` + control stream state
- [ ] Rewrite `WithKey()` option to use `ed25519.PrivateKey`
- [ ] Rewrite `dialOnce()` — custom handshake + yamux client session + open control stream
- [ ] Add `yamuxConfig()` helper
- [ ] Implement `readControlResponses()` — background goroutine dispatching responses by ID
- [ ] Implement `sendControl()` — request-reply over control stream with pending map
- [ ] Rewrite `sendListen()`/`sendListenWithDomain()` to use `sendControl()`
- [ ] Implement `acceptTunnelStreams()` replacing `handleChannels()`
- [ ] Rewrite `handleTunnel()` — read tunnel header via `readMsg`, dial local target
- [ ] Update `connectionLoop()` — use `session.CloseChan()` instead of `conn.Wait()`
- [ ] Rewrite `Close()` to close yamux session
- [ ] Rename `setSSH`/`getSSH` to `setSession`/`getSession`
- [ ] Remove all `golang.org/x/crypto/ssh` imports from client.go

### Task 5: Update tests and clean up
- [ ] Rewrite `TestAuthWrongPrivateKeyKnownPublic` in vtunnel_auth_test.go
- [ ] Remove deprecated SSH functions from wsconn.go: `keepAliveLoop`, `handleRequests`, `rejectChannels`, `generateHostKey`
- [ ] Remove SSH imports from wsconn.go
- [ ] Run `go mod tidy` to remove `golang.org/x/crypto`
- [ ] Run full test suite and fix any failures
- [ ] Verify no `golang.org/x/crypto/ssh` imports remain (except in tests if needed)

### Success criteria
- [ ] All existing tests pass (public API unchanged)
- [ ] No `golang.org/x/crypto/ssh` imports in non-test code
- [ ] yamux used for all stream multiplexing
- [ ] Custom ed25519 handshake replaces SSH auth
- [ ] Performance verification via bench tool (manual)

---

## 9. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| yamux keepalive semantics differ from SSH ping | yamux keepalive is similar: periodic ping, closes session on timeout. `TestKeepAliveDetectsSilentDrop` validates this. |
| Control stream closed unexpectedly | `readControlResponses()` cleans up all pending requests. Reconnect loop recreates everything. |
| `MaxStreamWindowSize = 16 MB` memory usage | 16 MB is per-stream send window. With N concurrent streams, memory is ~16 MB * N. Acceptable for tunnel use case (typically <100 concurrent streams). |
| No encryption without TLS | Document that `wss://` should be used in production. Same as current recommendation. |
| Breaking wire protocol | Acceptable: vtunnel is deployed as matched pairs. Keys and CLI flags preserved. |
