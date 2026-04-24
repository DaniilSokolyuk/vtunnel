# vtunnel

Route container/sandbox traffic to private services through a reverse tunnel.

Set `HTTPS_PROXY` in your sandbox — vtunnel intercepts outbound requests and routes configured domains through a tunnel to services only your machine can reach.

- **Control all outbound traffic** — route, inspect, or block any request leaving the container; only allowlisted domains go through the tunnel
- **Inject credentials outside the container** — API keys and tokens stay on the controlplane, never exposed to the sandbox or AI running inside it
- **Expose corporate resources** — make internal services (Nexus, Artifactory, GitLab) accessible inside the sandbox without VPN or network changes

```
 SANDBOX / CONTAINER              CONTROLPLANE (your machine)

┌──────────────────────┐        ┌──────────────────────────────────────────┐
│                      │        │                                          │
│ AI agent / dev tools │        │ vtunnel client                           │
│        │             │        │      │                                   │
│        ▼             │ TUNNEL │      ├─ api.anthropic.com                │
│ HTTPS_PROXY=:9090    │◀══════▶│      │   inject API key ───▶ anthropic   │
│        │             │        │      │                                   │
│ vtunnel server :3001 │        │      ├─ github.com                       │
│   + proxy :9090      │        │      │   inject PAT ───────▶ github      │
│   + mitm ca.pem      │        │      │                                   │
│                      │        │      ├─ nexus.corp                       │
│                      │        │      │   passthrough ──────▶ nexus       │
│                      │        │      │                                   │
│                      │        │      └─ * unmapped ────────▶ direct      │
│                      │        │                                          │
└──────────────────────┘        └──────────────────────────────────────────┘
```

Mapped domains go through the tunnel. Everything else passes through directly.

## Quick Start

**Server** (in container/sandbox):

```bash
vtunnel server -port 3001 -proxy 9090
```

**Client** (on your machine):

```bash
vtunnel client -server ws://container:3001/ \
  -forward gitlab.corp=gitlab.corp:443 \
  -forward jira.corp=jira.corp:443
```

**Use it:**

```bash
export HTTPS_PROXY=http://localhost:9090
git clone https://gitlab.corp/repo  # routed through tunnel
curl https://public-api.com         # direct, bypasses tunnel
```

## Install

```bash
go install github.com/DaniilSokolyuk/vtunnel/cmd/vtunnel@latest
```

Or grab a binary from [Releases](https://github.com/vivid-money/vtunnel/releases).

## Server

```bash
vtunnel server [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-port` | WebSocket listen port | `3001` |
| `-proxy` | HTTP CONNECT proxy port (0 = disabled) | `0` |
| `-proxy-mitm-ca` | PEM file with CA cert+key for HTTPS MITM | — |
| `-client-key` | Client public key (`vt-pub-...`) | `$VTUNNEL_CLIENT_KEY` |

`/health` returns `ok` for health checks.

## Client

```bash
vtunnel client [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-server` | WebSocket URL (required) | — |
| `-key` | Private key (`vt-priv-...`) | `$VTUNNEL_KEY` |
| `-forward` | Forward mapping (repeatable, at least 1) | — |
| `-H` / `-header` | Header injected into MITM-proxied requests for the preceding `-forward` (repeatable) | — |

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
- Injection happens inside the MITM path — the server needs `-proxy-mitm-ca` for headers to take effect.
- Values overwrite any same-named header the sandbox application sent (Set, not Add).

The Go library mirrors the CLI with `vtunnel.WithHeader`:

```go
client.Forward("api.example.test:443", "localhost:8081",
    vtunnel.WithHeader("Authorization", "Bearer sk-ant-xxx"),
    vtunnel.WithHeader("X-Env", "preview"),
)
```

## Authentication

```bash
vtunnel keygen
# Private key (client): vt-priv-...
# Public key (server):  vt-pub-...
```

```bash
vtunnel server -port 3001 -client-key "vt-pub-..."
vtunnel client -server ws://... -key "vt-priv-..." -forward ...
```

ed25519 SSH auth. Host key derived from client key — no manual host key exchange. Works without keys but insecure.

## HTTPS MITM

By default the proxy tunnels TLS end-to-end. This works for passthrough (`gitlab.corp=gitlab.corp:443`) but fails when the backend is plain HTTP (`myapi.local=localhost:8080`).

Provide a CA to intercept:

```bash
vtunnel server -proxy 9090 -proxy-mitm-ca ca.pem
```

The proxy terminates TLS, generates certs on the fly, and forwards plain HTTP to the backend. Clients must trust the CA.

## How It Works

SSH protocol over WebSocket — multiplexed channels, encryption, and auth for free. Passes through firewalls and HTTP proxies. Auto-reconnect with exponential backoff. Server listeners persist across reconnections.

## Go Library

See [pkg.go.dev](https://pkg.go.dev/github.com/DaniilSokolyuk/vtunnel) and [example/](example/).

## License

MIT
