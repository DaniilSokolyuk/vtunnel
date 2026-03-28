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

**Port** — server opens a TCP port, tunnels all connections:

```bash
-forward 9000=localhost:3000

# Same client-side TLS, but port-based
-forward 8085=tls://www.google.com:443
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
