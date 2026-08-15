# vtunnel

Route container/sandbox traffic to private services through a reverse tunnel.

Set `HTTPS_PROXY` in your sandbox — vtunnel intercepts outbound requests and routes configured domains through a tunnel to services only your machine can reach.

- **Control all outbound traffic** — route, inspect, or block any request leaving the container; only allowlisted domains go through the tunnel
- **Inject credentials outside the container** — API keys, tokens and the MITM CA private key live on the controlplane and never enter the sandbox. The container holds a domain allowlist and a CA certificate, nothing more
- **Expose corporate resources** — make internal services (Nexus, Artifactory, GitLab) accessible inside the sandbox without VPN or network changes

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

The sandbox never terminates TLS. Its proxy reads the domain from the `CONNECT` request line — which the application sends in cleartext, before any TLS — and chains matching requests to the controlplane, which is the only side that decrypts and injects.

## Quick Start

**1. Make the CA on your machine.** It writes two files: the pair to keep, and
the certificate to hand out.

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

## Server

```bash
vtunnel server [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-port` | WebSocket listen port | `3001` |
| `-proxy` | Routing proxy port (0 = disabled) | `0` |
| `-client-key` | Client public key (`vt-pub-...`) | `$VTUNNEL_CLIENT_KEY` |

The server takes no CA: it cannot intercept TLS by design.

`/health` returns `ok` for health checks.

## Client

```bash
vtunnel client [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-server` | WebSocket URL (required) | — |
| `-key` | Private key (`vt-priv-...`) | `$VTUNNEL_KEY` |
| `-mitm-ca` | PEM file with CA cert+key for HTTPS MITM; created if missing. Without it TLS is piped through untouched and `-H` is rejected | `$VTUNNEL_MITM_CA` (unset = no interception) |
| `-forward` | Forward mapping (repeatable, at least 1) | — |
| `-H` / `-header` | Header injected into requests for the preceding `-forward` (repeatable) | — |

### Forward formats

**Domain** — proxy routes by hostname, no port allocation needed:

```bash
# Passthrough: proxy → tunnel → client → real host as-is
-forward gitlab.corp=gitlab.corp:443

# Route to a local service on the client side
-forward myapi.local=localhost:8080

# Client-side TLS: proxy decrypts via MITM, sends plain HTTP through tunnel,
# client re-encrypts and connects to the real host over TLS
-forward myapi.local=tls://api.example.com:443
```

A domain without a port registers on both `:80` and `:443`.

**Wildcard domain** — match a family of hostnames with one entry:

```bash
# All subdomains of example.test → one local service
-forward *.example.test=localhost:8080

# All hosts starting with mail. → one local service
-forward mail.*=localhost:8080
```

Rules:

- `*` must be a **complete label on a dot border**, either the leftmost (`*.example.test`) or the rightmost (`mail.*`). Middle or partial-label asterisks (`a.*.b`, `w*.example.test`) are treated as literal strings.
- Matches **one or more** extra labels: `*.example.test` matches `a.example.test` and `a.b.example.test`, but not the apex `example.test`. `mail.*` matches `mail.example.test` and `mail.foo.example.test`, but not `mail` alone.
- **Priority**: exact forwards win over wildcards; among wildcards, leftmost beats rightmost; within a group, the longer pattern wins.
- Per-subdomain routing on the client side is the controlplane's job — vtunnel just delivers every matching request to the configured target.

**Port** — server opens a TCP port, tunnels all connections:

```bash
-forward 9000=localhost:3000

# Same client-side TLS, but port-based
-forward 8085=tls://www.google.com:443
```

### Inject headers

The MITM proxy can inject HTTP headers into requests forwarded for a specific domain — useful when the controlplane holds credentials that the sandbox application shouldn't see:

```bash
vtunnel client -server ws://... \
  -forward api.example.test=localhost:8081 \
    -H 'Authorization: Bearer sk-ant-xxx' \
    -H 'X-Env: preview' \
  -forward auth.example.test=localhost:8082 \
    -H 'Authorization: Basic <token>' \
  -forward plain.example.test=plain.example.test:443
```

Rules:

- Each `-H` attaches to the **most recent** `-forward`. Order matters.
- Only domain-flavored forwards (not port-flavored) accept `-H`.
- Values never cross the tunnel. The sandbox is told the domain name; the header is applied on this machine.
- Injection happens inside the MITM path, so it needs `-mitm-ca`. Without it the flag is rejected at startup rather than silently ignored.
- Values overwrite any same-named header the sandbox application sent (Set, not Add).
- Cleartext h2c gRPC over an HTTP/1.1 CONNECT tunnel is terminated without TLS (no cert needed), so headers are injected there too. Other cleartext falls back to a raw byte pipe, where injection is skipped and a `WARNING` is logged.

The Go library mirrors the CLI:

```go
client := vtunnel.NewClient(wsURL, vtunnel.WithMitm(ca))
client.Forward("api.example.test:443", "localhost:8081",
    vtunnel.WithHeader("Authorization", "Bearer sk-ant-xxx"),
    vtunnel.WithHeader("X-Env", "preview"),
)
```

`Forward` and `Unforward` may be called at any time while connected; each call re-sends the full domain list, which the sandbox router applies wholesale. Existing pooled connections keep their old route until they are re-established.

## Authentication

```bash
vtunnel keygen
# Private key (client): vt-priv-...
# Public key (server):  vt-pub-...
```

This is the tunnel's own authentication and has nothing to do with the MITM CA — see [HTTPS MITM](#https-mitm) for that.

```bash
vtunnel server -port 3001 -client-key "vt-pub-..."
vtunnel client -server ws://... -key "vt-priv-..." -forward ...
```

ed25519 SSH auth. Host key derived from client key — no manual host key exchange. Works without keys but insecure.

## HTTPS MITM

Interception happens on the **controlplane**, never in the sandbox: the client signs short-lived leaf certificates on the fly from a CA that stays on your machine.

A CA is a private key plus a self-signed **certificate** — the certificate is
the public half, because trust stores validate chains and need the name, the
validity window and the `IsCA` flag, not a bare public key. `vtunnel ca` writes
both, the way mitmproxy does:

```bash
vtunnel ca
```

| File | Contains | Mode | Goes |
|---|---|---|---|
| `ca.pem` | certificate + private key | `0600` | stays here, `-mitm-ca` reads it |
| `ca.crt` | certificate only | `0644` | into the sandbox trust store |

Both land in the working directory. `ca.pem` can mint certificates every
sandbox trusts — keep it out of version control.

Running it again re-exports the certificate from the existing CA — it never
silently replaces one that sandboxes already trust.

`-mitm-ca` names the pair, and is the same flag (and the same file) the client
takes; `-out` picks a different path for the certificate, `-stdout` pipes it
instead of writing. To adopt a CA made elsewhere, point `-mitm-ca` at it with
its certificate and key in one PEM.

Then, in the sandbox:

```bash
cp ca.crt /usr/local/share/ca-certificates/vtunnel-ca.crt && update-ca-certificates
```

Interception is on exactly when `-mitm-ca` is given (the file is created if it does not exist). Without it, forwarded TLS is piped through untouched — and `-H` is rejected rather than silently ignored, since a header can only be injected into traffic the proxy terminates.

The proxy establishes the upstream connection before finishing the client handshake, so the protocol it offers the application is one the upstream actually supports, rather than a blind `h2`/`http/1.1` guess.

### Wiring the sandbox

`update-ca-certificates` only populates the **system** trust store, and plenty
of runtimes ship their own. Rather than chase each one, point them all at the
same bundle — the system one, which now contains the MITM CA:

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

Add anything else you route through the tunnel and want kept local to
`NO_PROXY` — an internal registry mirror, for instance, gains nothing from the
extra hop.

Two things this still cannot fix: a runtime with its own keystore that ignores
these variables (Java wants `keytool -importcert` into the JDK cacerts), and
certificate pinning, which rejects any CA by design. Leave pinned domains
unmapped, or forward them without `-H` so their TLS passes through untouched.

## How It Works

SSH protocol over WebSocket — multiplexed channels, encryption, and auth for free. Passes through firewalls and HTTP proxies. Auto-reconnect with exponential backoff. Server listeners persist across reconnections.

The only thing the controlplane tells the sandbox is a list of domain names, on one `listen` request. Targets, headers and the CA stay behind.

## Go Library

The package documentation covers the architecture and both sides of the tunnel;
runnable examples live in `example_test.go`.

```go
client := vtunnel.NewClient("ws://sandbox:3001/", vtunnel.WithMitm(ca))
client.Connect()
defer client.Close()

client.Forward("api.corp", "localhost:8081",
    vtunnel.WithHeader("Authorization", "Bearer "+token))
```

See [pkg.go.dev](https://pkg.go.dev/github.com/vivid-money/vtunnel) and [example/](example/).

## Migrating to 0.7

Coming from 0.6.x. TLS interception moved out of the sandbox: the private CA
key and the injected credentials now live only on the controlplane, and the
sandbox keeps a domain allowlist and a CA certificate.

**The wire protocol changed** — a 0.7 client cannot drive a 0.6 server, or the
reverse. Both sides upgrade together.

### Steps

**1. Generate the CA on the controlplane** (safe to do before upgrading — it
changes nothing yet):

```bash
vtunnel ca   # ca.pem stays here; ca.crt goes to the sandbox
```

Already have a CA you want to keep, so sandboxes need no new trust anchor? Put
its cert and key in one PEM and pass it as `-mitm-ca thatfile.pem` — to
`vtunnel ca` here, and to `vtunnel client` in step 3.

**2. Install `ca.crt` in the sandbox image** — the certificate only:

```dockerfile
COPY ca.crt /usr/local/share/ca-certificates/vtunnel-ca.crt
RUN update-ca-certificates
```

Delete whatever generated a CA inside the image. That key was the thing this
release exists to remove — treat it as compromised and stop using it.

**3. Upgrade both binaries and move the CA flag from server to client:**

```diff
 # in the sandbox
-vtunnel server -port 3001 -proxy 9090 -proxy-mitm-ca /etc/vtunnel-ca.pem
+vtunnel server -port 3001 -proxy 9090

 # on your machine
-vtunnel client -server ws://sandbox:3001/ -forward api.corp=localhost:8081 -H '...'
+vtunnel client -server ws://sandbox:3001/ -mitm-ca ca.pem \
+  -forward api.corp=localhost:8081 -H '...'
```

`-mitm-ca` is what turns interception on; the file is created if missing, so
step 1 and this flag name the same `ca.pem`. Omit it and TLS is piped through
untouched — in which case `-H` is rejected, because there is nothing to inject
into.

**4. Verify.** From inside the sandbox, a mapped domain should still work, and
the container should no longer hold a key:

```bash
curl https://api.corp/health           # works, credential injected outside
ls /etc/vtunnel-ca.pem                 # should not exist
```

`-forward`, `-H`, `-key` and `vtunnel keygen` are unchanged.

### API changes

| Before (0.6) | Now (0.7) |
|---|---|
| `vtunnel.WithProxyMitmCA(cert)` — ServerOption | `vtunnel.WithMitm(cert)` — Option, on the client |
| `server.SetDomainMapping` / `SetDomainHeaders` | removed; routes arrive over the tunnel from `client.Forward` |
| `server.StartProxy` starts a MITM proxy | starts the routing proxy; interception is on the client |
| headers travelled to the sandbox in the listen request | headers never leave the controlplane |
| — | `client.Unforward(domain)` drops a forward while connected |
| — | `vtunnel.GenerateCA` / `CACertPEM` / `LoadCA` |

`client.Forward`, `client.Listen` and `vtunnel.WithHeader` keep their signatures
and behaviour.

### Rollback

Downgrade both sides together. The 0.6 sandbox image needs its own CA back, so
keep the old image tag around until you are satisfied.

## License

MIT
