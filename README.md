# vtunnel

Route container/sandbox traffic to private services through a reverse tunnel, and intercept it on a machine the sandbox cannot reach.

Set `HTTPS_PROXY` in your sandbox — vtunnel routes configured domains through a tunnel to services only your machine can reach, and injects credentials the container never holds.

- **Control all outbound traffic** — route, inspect, rewrite or block any request leaving the container; only allowlisted domains go through the tunnel
- **Inject credentials outside the container** — API keys, tokens and the MITM CA private key live on the controlplane and never enter the sandbox. The container holds a domain allowlist and a CA certificate, nothing more
- **Expose corporate resources** — make internal services (Nexus, Artifactory, GitLab) reachable inside the sandbox without VPN or network changes

```
 SANDBOX / CONTAINER             CONTROLPLANE (your machine)

┌───────────────────────┐        ┌────────────────────────────────────┐
│ AI agent / dev tools  │        │ vtunnel client                     │
│        │              │        │   + MITM proxy                     │
│        ▼              │ TUNNEL │   + CA private key                 │
│ HTTPS_PROXY=:9090     │◀══════▶│   + credentials                    │
│        │              │        │      │                             │
│ vtunnel server :3001  │        │      ├─ api.anthropic.com          │
│   + router :9090      │        │      │    inject key ──▶ anthropic │
│                       │        │      │                             │
│ routes by domain,     │        │      ├─ github.com                 │
│ never decrypts:       │        │      │    inject PAT ──▶ github    │
│ no CA, no secrets     │        │      │                             │
│                       │        │      └─ nexus.corp                 │
│ unmapped ──▶ internet │        │           passthrough ──▶ nexus    │
└───────────────────────┘        └────────────────────────────────────┘
```

Mapped domains go through the tunnel. Everything else egresses from the sandbox directly.

vtunnel is two pieces that work together and ship in one binary, documented separately below because they are separable in practice:

- **[The tunnel](#the-tunnel)** — a reverse tunnel between the sandbox and your machine, plus a router in the sandbox that dispatches by domain name and never decrypts anything.
- **[The MITM proxy](#the-mitm-proxy)** — an intercepting forward proxy on the controlplane. It holds the CA, the real targets and the credentials. It depends on neither side of the tunnel and [runs perfectly well on its own](#using-it-without-a-tunnel).

## Contents

- [Quick start](#quick-start)
- [Install](#install)
- [**The tunnel**](#the-tunnel)
  - [How it works](#how-it-works)
  - [Sandbox side](#sandbox-side)
  - [Controlplane side](#controlplane-side)
  - [Authentication](#authentication)
  - [Raw port forwards](#raw-port-forwards)
  - [Reconnection](#reconnection)
- [**The MITM proxy**](#the-mitm-proxy)
  - [Routes](#routes)
  - [Wildcard domains](#wildcard-domains)
  - [Injecting headers](#injecting-headers)
  - [The CA](#the-ca)
  - [Wiring the sandbox](#wiring-the-sandbox)
  - [Protocols](#protocols)
  - [Streaming responses](#streaming-responses)
  - [WebSocket and other upgrades](#websocket-and-other-upgrades)
  - [Inspecting and rewriting traffic](#inspecting-and-rewriting-traffic)
  - [When interception cannot work](#when-interception-cannot-work)
  - [Shutting down](#shutting-down)
  - [Debugging an intercepted session](#debugging-an-intercepted-session)
  - [Using it without a tunnel](#using-it-without-a-tunnel)
- [CLI reference](#cli-reference)
- [Go library](#go-library)
- [License](#license)

## Quick start

**1. Make the CA on your machine.** It writes two files: the pair to keep, and the certificate to hand out.

```bash
vtunnel ca
# private key + cert  ca.pem   keep here, pass to: vtunnel client -mitm-ca
# certificate only    ca.crt   copy into the sandbox trust store
```

```bash
# in the container
cp ca.crt /usr/local/share/ca-certificates/vtunnel-ca.crt && update-ca-certificates
```

**2. Server** (in container/sandbox) — routes by domain, never decrypts:

```bash
vtunnel server -port 3001 -proxy 9090
```

**3. Client** (on your machine) — holds the CA, the targets and the credentials:

```bash
vtunnel client -server ws://container:3001/ -mitm-ca ca.pem \
  -forward gitlab.corp=gitlab.corp:443 \
  -forward jira.corp=jira.corp:443
```

**4. Use it:**

```bash
export HTTPS_PROXY=http://localhost:9090
git clone https://gitlab.corp/repo  # routed through tunnel
curl https://public-api.com         # direct, bypasses tunnel
```

## Install

```bash
go install github.com/vivid-money/vtunnel/cmd/vtunnel@latest
```

Or grab a binary from [Releases](https://github.com/vivid-money/vtunnel/releases).

Upgrading from 0.6.x? Interception moved out of the sandbox and the wire protocol changed — see [MIGRATING.md](MIGRATING.md).

---

# The tunnel

## How it works

SSH over WebSocket — multiplexed channels, encryption and authentication for free, through firewalls and corporate HTTP proxies. Implemented in [`server.go`](server.go), [`client.go`](client.go) and [`wsconn.go`](wsconn.go).

**The client dials in.** A [`Server`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Server) runs inside the sandbox and accepts a WebSocket; a [`Client`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Client) runs on your machine and connects to it. The sandbox therefore needs no route back out to you, and no inbound port beyond the one the tunnel arrives on.

**The two sides are deliberately unequal.** The [`Router`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Router) in the sandbox ([`router.go`](router.go)) holds a list of domain names and nothing else. It reads the domain from the `CONNECT` request line — which the application sends in cleartext, before any TLS — and either chains the connection to the controlplane or dials it directly. It has no CA and cannot decrypt.

**Only domain names cross the tunnel.** Targets, injected headers and the CA private key never do. The controlplane sends the sandbox one list of names; everything else stays behind.

## Sandbox side

```bash
vtunnel server -port 3001 -proxy 9090
```

The server takes no CA: it cannot intercept TLS by design. `/health` returns `ok` for health checks.

As a library:

```go
server := vtunnel.NewServer(vtunnel.WithClientKey(publicKey))
server.StartProxy(":9090") // the application's HTTPS_PROXY

http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        return
    }
    defer conn.Close()
    server.HandleConn(conn)
})
http.ListenAndServe(":3001", nil)
```

## Controlplane side

```bash
vtunnel client -server ws://container:3001/ -mitm-ca ca.pem -forward api.corp=localhost:8081
```

As a library — routes are declared on the proxy the client owns, and the client mirrors their domain names into the sandbox as they appear:

```go
ca, _ := vtunnel.LoadCA(pemBytes) // cert+key from ca.pem; the key stays here

client := vtunnel.NewClient("ws://sandbox:3001/",
    vtunnel.WithKey(privateKey),
    vtunnel.WithMitm(ca),
)
client.Connect()
defer client.Close()

client.Proxy().ForwardTo("api.corp", "localhost:8081",
    vtunnel.WithHeader("Authorization", "Bearer "+token))
```

Routes may be changed at any time while connected. Each change re-sends the full domain list, which the sandbox applies wholesale; connections already established keep their old route until they are re-established.

## Authentication

```bash
vtunnel keygen
# Private key (client): vt-priv-...
# Public key (server):  vt-pub-...

vtunnel server -port 3001 -client-key "vt-pub-..."
vtunnel client -server ws://... -key "vt-priv-..." -forward ...
```

ed25519 SSH auth ([`auth.go`](auth.go)). The host key is derived from the client key, so there is no manual host key exchange. It works without keys, insecurely.

This is the tunnel's own authentication and has nothing to do with the MITM CA — see [The CA](#the-ca) for that.

## Raw port forwards

Independent of all domain routing: the server opens a TCP port in the sandbox and pipes every connection to a local address, with no HTTP parsing and no interception.

```bash
-forward 9000=localhost:3000
-forward 8085=tls://www.google.com:443   # the client wraps the connection in TLS
```

```go
client.Listen(9000, "localhost:3000")
client.Listen(8085, "tls://www.google.com:443")
```

## Reconnection

Automatic, with exponential backoff. Server-side listeners persist across reconnections, and forwards are replayed once the tunnel is back, so a dropped link recovers without intervention. Tunable with [`WithReconnectBackoff`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithReconnectBackoff), [`WithKeepAlive`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithKeepAlive) and [`WithPingInterval`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithPingInterval); [`WithHeaders`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithHeaders) adds WebSocket headers for a corporate proxy in the way. Covered by [`vtunnel_reconnect_test.go`](vtunnel_reconnect_test.go).

---

# The MITM proxy

[`MITMProxy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy) ([`mitmproxy.go`](mitmproxy.go), [`mitm.go`](mitm.go)) is the side that decrypts, rewrites and talks to upstreams. Interception happens here, on the **controlplane**, never in the sandbox: the proxy signs short-lived leaf certificates on the fly from a CA that stays on your machine.

## Routes

A domain is served in exactly one of three shapes. Which one you pick decides what is possible with it.

| | What happens | Needs a CA | Can inject headers |
|---|---|---|---|
| [`ForwardTo(domain, target)`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.ForwardTo) | TLS is terminated and the request re-issued to `target` | yes | **yes** |
| [`Handle(domain, h)`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.Handle) | served by your `http.Handler` in this process; no upstream connection at all | yes | n/a |
| [`Forward(domain)`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.Forward) | piped to the host the client asked for, TLS untouched | no | no |

`Forward` is the only shape that works against an upstream that pins certificates, precisely because nothing is terminated.

Anything in the "needs a CA" column is **refused when no CA is configured**, at the point the route is declared rather than on every request that reaches it. Injection happens after TLS is terminated, so on a proxy that cannot terminate it a route carrying headers would answer requests perfectly normally and simply never add the credential — a failure with no error to see. A CA-less proxy is still fully useful for routing and passthrough; it just cannot promise what it cannot do.

Anything with no route is dialled directly. [`HandleUnmapped`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.HandleUnmapped) changes that — a controlplane proxy usually wants to refuse, so a compromised tunnel cannot turn it into an open relay:

```go
proxy.HandleUnmapped(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    http.Error(w, "unknown domain", http.StatusForbidden)
}))
```

A target may be a plain address (`localhost:8080`), or `tls://host:port` to have the proxy re-encrypt on the way out, with [`WithSNI`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithSNI) when the certificate is issued for a name the address does not carry. A domain given without a port registers on both `:80` and `:443`.

## Wildcard domains

One entry matches a family of hostnames. The same matcher serves both sides of the tunnel ([`proxyshared.go`](proxyshared.go)), so a host resolves identically in the sandbox and on the controlplane.

```bash
-forward '*.example.test=localhost:8080'   # all subdomains
-forward 'mail.*=localhost:8080'           # all hosts starting with mail.
```

- `*` must be a **complete label on a dot border**, either leftmost (`*.example.test`) or rightmost (`mail.*`). Middle or partial-label asterisks (`a.*.b`, `w*.example.test`) are literal strings.
- Matches **one or more** extra labels: `*.example.test` matches `a.example.test` and `a.b.example.test`, but not the apex `example.test`.
- **Priority**: exact beats wildcard; leftmost beats rightmost; within a group, the longer pattern wins.

Covered by [`proxy_wildcard_test.go`](proxy_wildcard_test.go).

## Injecting headers

The point of the whole arrangement: a credential the sandbox application never receives.

```bash
vtunnel client -server ws://... -mitm-ca ca.pem \
  -forward api.example.test=localhost:8081 \
    -H 'Authorization: Bearer sk-ant-xxx' \
    -H 'X-Env: preview' \
  -forward plain.example.test=plain.example.test:443
```

```go
client.Proxy().ForwardTo("api.example.test:443", "localhost:8081",
    vtunnel.WithHeader("Authorization", "Bearer sk-ant-xxx"),
    vtunnel.WithHeader("X-Env", "preview"),
)
```

- Each `-H` attaches to the **most recent** `-forward`; order matters. Only domain forwards accept it, not port forwards.
- Values never cross the tunnel. The sandbox is told the domain name; the header is applied on this machine.
- Values overwrite any same-named header the application sent (Set, not Add).
- Injection needs interception, so it needs `-mitm-ca`. Without it the flag is rejected at startup rather than silently ignored.
- Cleartext h2c gRPC over an HTTP/1.1 `CONNECT` is terminated without TLS, so headers are injected there too. Other cleartext falls back to a raw byte pipe, where injection is skipped and a `WARNING` is logged.
- A WebSocket handshake is an ordinary request, so configured headers land in it — see [WebSocket](#websocket-and-other-upgrades).

Covered by [`header_injection_test.go`](header_injection_test.go).

## The CA

A CA is a private key plus a self-signed **certificate** — the certificate is the public half, because trust stores validate chains and need the name, the validity window and the `IsCA` flag, not a bare public key. `vtunnel ca` writes both, the way mitmproxy does:

```bash
vtunnel ca
```

| File | Contains | Mode | Goes |
|---|---|---|---|
| `ca.pem` | certificate + private key | `0600` | stays here, `-mitm-ca` reads it |
| `ca.crt` | certificate only | `0644` | into the sandbox trust store |

Both land in the working directory. `ca.pem` can mint certificates every sandbox trusts — keep it out of version control. Running the command again re-exports the certificate from the existing CA; it never silently replaces one that sandboxes already trust.

`-out` picks a different path for the certificate, `-stdout` pipes it instead of writing. To adopt a CA made elsewhere, point `-mitm-ca` at a PEM holding its certificate and key.

Interception is on exactly when `-mitm-ca` is given (in the library, [`WithMitm`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithMitm)). Without it, forwarded TLS is piped through untouched.

Leaf certificates are generated per hostname and cached ([`mitm.go`](mitm.go)). Each gets **its own key** rather than sharing the CA's, they are short-lived and renewed ahead of expiry, the cache is bounded, and simultaneous first requests for the same host produce one certificate rather than one per connection.

## Wiring the sandbox

`update-ca-certificates` only populates the **system** trust store, and plenty of runtimes ship their own. Rather than chase each one, point them all at the same bundle — the system one, which now contains the MITM CA:

```dockerfile
ENV HTTP_PROXY=http://localhost:9090
ENV HTTPS_PROXY=http://localhost:9090
ENV ALL_PROXY=http://localhost:9090
# localhost so the daemons in here do not proxy to themselves
ENV NO_PROXY=localhost,127.0.0.1
ENV NODE_USE_ENV_PROXY=1

# One CA bundle for everything. It is the system store, which already contains
# vtunnel's MITM CA (added by update-ca-certificates above), so each of these
# just points its own client library at the same file.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt
ENV UV_SYSTEM_CERTS=true
```

Add anything you route through the tunnel but want kept local to `NO_PROXY` — an internal registry mirror, for instance, gains nothing from the extra hop.

Two things this cannot fix: a runtime with its own keystore that ignores these variables (Java wants `keytool -importcert` into the JDK cacerts), and certificate pinning — see [When interception cannot work](#when-interception-cannot-work).

## Protocols

HTTP/1.1 and HTTP/2 on both legs, plus cleartext h2c inside a `CONNECT` tunnel.

**ALPN is mirrored, not guessed.** The proxy establishes the upstream connection before finishing the client's handshake, so the protocol it offers the application is one the upstream actually supports. When the client's ALPN excludes what the upstream settled on, the proxy translates between the two instead of failing the handshake — it re-issues requests rather than piping them, so the two sides need not agree ([`proxy_alpn_mirror_test.go`](proxy_alpn_mirror_test.go)).

**gRPC works, trailers included.** `grpc-status` arrives after the body, so it is forwarded separately from the headers; unannounced trailers are handled too ([`proxy_trailers_test.go`](proxy_trailers_test.go), [`proxy_grpcurl_test.go`](proxy_grpcurl_test.go)). Cleartext h2c over `CONNECT` is terminated without a certificate, which is what makes header injection into plain gRPC possible ([`proxy_h2c_connect_fallback_test.go`](proxy_h2c_connect_fallback_test.go)).

**Compression passes through correctly.** If the application asked for `gzip`, the compressed bytes are forwarded untouched with `Content-Encoding` intact. If it did not, the proxy's own transport asks for compression, decompresses, and drops the header — so the body and the headers describing it always agree ([`proxy_gzip_test.go`](proxy_gzip_test.go)).

## Streaming responses

Server-sent events are delivered event by event, not batched at end-of-body — an agent that depends on incremental `text/event-stream` from an LLM API behaves as if the response arrived empty otherwise. Every path the proxy can serve a route on has its own copy loop, and all of them are covered: HTTP/1.1, HTTP/2, an h2 client against an HTTP/1.1 upstream, a `tls://` upstream, an in-process handler, a raw pipe and plain HTTP ([`proxy_sse_matrix_test.go`](proxy_sse_matrix_test.go)).

Streaming survives compression and header injection too.

## WebSocket and other upgrades

Upgrades are **spliced, not re-terminated**. The handshake is re-issued as an ordinary request, so headers configured for the route land inside it; once the upstream answers `101`, the two connections are joined and nothing further is parsed.

That is what keeps the negotiation between the endpoints: **subprotocols, `permessage-deflate` and frame boundaries survive exactly as agreed**. A proxy that terminates the WebSocket in the middle has to re-negotiate both and in practice drops compression.

Works on every route shape and on both transports — `wss` through `CONNECT`, and cleartext `ws://` through the sandbox router, which cannot use an ordinary HTTP transport because it has no way to return a `101`. Covered by [`proxy_websocket_test.go`](proxy_websocket_test.go); see [`ExampleMITMProxy_ForwardTo_webSocket`](example_test.go).

## Inspecting and rewriting traffic

[`Use`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.Use) attaches middleware to every request the proxy terminates, handler routes and forwarded ones alike. Requests that are only piped through are never parsed, so they never reach it.

```go
proxy.Use(func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("%s %s%s", r.Method, r.Host, r.URL.Path)
        next.ServeHTTP(w, r)
    })
})
```

Middleware is also where **response bodies and WebSocket frames** are reachable, by substituting the `http.ResponseWriter`. Two obligations come with that, and both are easy to miss:

- **Implement `Unwrap() http.ResponseWriter`.** Incremental delivery depends on the proxy flushing after every write, and `http.ResponseController` finds the flusher by unwrapping. Without it an SSE stream stops at its first event. See [`ExampleMITMProxy_Use_serverSentEvents`](example_test.go).
- **Forward `http.Hijacker`** to observe an upgraded connection — and wrap the `*bufio.ReadWriter` that `Hijack` returns as well. The proxy reads through that reader, so replacing only the `net.Conn` shows you writes and silently hides every read. See [`ExampleMITMProxy_Use_webSocketTap`](example_test.go).

Changing WebSocket frames rather than only watching them is the same hook plus a frame codec, which the proxy deliberately does not provide: parsing frames means deciding what to do about compression, fragmentation and control frames, and a caller that wants none of that should not pay for it. [`ExampleMITMProxy_Use_webSocketRewrite`](example_test.go) shows the smallest version that works, and is explicit about its limits.

## When interception cannot work

Some upstreams cannot be intercepted at all: a client that pins certificates refuses the generated leaf every time, and an upstream demanding mutual TLS refuses the proxy every time. Rather than failing identically on every request, the proxy notices and stops trying — the domain is piped through untouched for the next 10 minutes, with a `WARNING` naming it. Interception resumes afterwards, so installing the CA in the client takes effect without a restart.

Two cases deliberately keep failing instead:

- a forward carrying `-H`, because a request that quietly kept working without its credential would hide the problem rather than report it;
- a domain served in-process, which has no upstream to fall back to.

Domains known to pin can be declared up front, so not even the first request is spent discovering it:

```go
proxy.MITMExceptions("pinned.example.com")
```

Covered by [`proxy_mitm_exceptions_test.go`](proxy_mitm_exceptions_test.go); see [`ExampleMITMProxy_MITMExceptions`](example_test.go).

## Shutting down

[`Close`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.Close) stops immediately: the listener goes down and every connection still open is dropped, including `CONNECT` tunnels and the servers running on top of them.

[`Shutdown(ctx)`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.Shutdown) lets requests already in flight finish first, and gives up at the deadline. A byte pipe and an open stream have no request boundary to wait for, so those are only ever ended by the deadline — give the context a bound you are willing to wait for.

Either way the teardown reaches **past the proxy**: closing the client connection cancels the handler's request context, which aborts the upstream round trip and closes its body, so a streaming upstream stops streaming instead of billing for tokens nobody reads ([`proxy_shutdown_test.go`](proxy_shutdown_test.go)).

## Debugging an intercepted session

Set `SSLKEYLOGFILE` and the proxy appends the session keys of both legs — application↔proxy and proxy↔upstream — to that file, which is what Wireshark needs to show the decrypted stream:

```bash
SSLKEYLOGFILE=/tmp/vtunnel-keys.log vtunnel client -server ws://... -mitm-ca ca.pem -forward ...
```

The file is created `0600`, but it still makes every session it covers readable to anyone who obtains it. Use it while debugging on your own machine and leave it unset everywhere else.

## Using it without a tunnel

`MITMProxy` depends on neither `Server` nor `Client`. Given a CA and a listen address it is a complete intercepting forward proxy on its own — useful for local development, tests, or anywhere the "sandbox" is just another process on the same host:

```go
ca, _ := vtunnel.LoadCA(pemBytes)

proxy := vtunnel.NewMITMProxy(vtunnel.WithMitmCA(ca))
proxy.Start("127.0.0.1:0")     // Addr() reports the port it picked
defer proxy.Close()

proxy.ForwardTo("api.test:443", "localhost:8081",
    vtunnel.WithHeader("Authorization", "Bearer local-token"))
```

Point `HTTPS_PROXY` at `proxy.Addr()` and trust the CA. See [`mitmproxy_standalone_test.go`](mitmproxy_standalone_test.go).

---

## CLI reference

### `vtunnel server`

| Flag | Description | Default |
|------|-------------|---------|
| `-port` | WebSocket listen port | `3001` |
| `-proxy` | Routing proxy port (0 = disabled) | `0` |
| `-client-key` | Client public key (`vt-pub-...`) | `$VTUNNEL_CLIENT_KEY` |

### `vtunnel client`

| Flag | Description | Default |
|------|-------------|---------|
| `-server` | WebSocket URL (required) | — |
| `-key` | Private key (`vt-priv-...`) | `$VTUNNEL_KEY` |
| `-mitm-ca` | PEM with CA cert+key for HTTPS MITM; created if missing. Without it TLS is piped through untouched and `-H` is rejected | `$VTUNNEL_MITM_CA` (unset = no interception) |
| `-forward` | Forward mapping (repeatable, at least one required) | — |
| `-H` / `-header` | Header injected into requests for the preceding `-forward` (repeatable) | — |

### `vtunnel ca`

| Flag | Description | Default |
|------|-------------|---------|
| `-mitm-ca` | PEM with CA cert+key (created if missing) | `$VTUNNEL_MITM_CA`, else `ca.pem` |
| `-out` | Where to write the certificate | alongside the CA, as `.crt` |
| `-stdout` | Print the certificate instead of writing a file | `false` |

### `vtunnel keygen`

Prints a fresh ed25519 pair: the private key for the client, the public key for the server.

### `-forward` formats

```bash
# Route the domain to itself, TLS untouched. No target means no interception,
# which is what an upstream that pins certificates needs. -H does not apply.
-forward gitlab.corp

# Intercepted and re-issued to the real host — the form to use when you want
# headers injected into it.
-forward gitlab.corp=gitlab.corp:443

# Route to a service on the controlplane
-forward myapi.local=localhost:8080

# Controlplane-side TLS: intercepted, sent as plain HTTP through the tunnel,
# re-encrypted by the client on the way to the real host
-forward myapi.local=tls://api.example.com:443

# Wildcards
-forward '*.example.test=localhost:8080'
-forward 'mail.*=localhost:8080'

# Port forward: the server opens a TCP port and tunnels every connection
-forward 9000=localhost:3000
-forward 8085=tls://www.google.com:443
```

## Go library

Package documentation covers the architecture and both sides of the tunnel; runnable, output-verified examples live in [`example_test.go`](example_test.go) and a full container-plus-controlplane setup in [`example/`](example/).

```go
client := vtunnel.NewClient("ws://sandbox:3001/", vtunnel.WithMitm(ca))
client.Connect()
defer client.Close()

client.Proxy().ForwardTo("api.corp", "localhost:8081",
    vtunnel.WithHeader("Authorization", "Bearer "+token))
```

See [pkg.go.dev](https://pkg.go.dev/github.com/vivid-money/vtunnel).

## License

MIT
