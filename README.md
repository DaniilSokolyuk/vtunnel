# vtunnel

[![Go Reference](https://pkg.go.dev/badge/github.com/vivid-money/vtunnel.svg)](https://pkg.go.dev/github.com/vivid-money/vtunnel)

A reverse tunnel with a full TLS-intercepting proxy on the far end. Set `HTTPS_PROXY` in a container and the domains you choose come out on your machine, decrypted, as ordinary Go requests. The CA, the real targets and the credentials stay there; the container gets a list of domain names and a CA certificate, nothing else.

## Features

**Tunnel**

* Reverse — the client dials in; the sandbox needs no route back out
* Transports `ws` / `wss` / `tcp`, or a `net.Conn` of your own; sessions SSH or yamux over TLS 1.3 pinned to a shared secret
* Domain routing in the sandbox, without decrypting anything
* Egress rules the sandbox enforces: CIDRs, addresses and wildcard names, allow or deny
* Only domain names and those rules cross the tunnel — no targets, no credentials, no CA
* Raw TCP port forwards; reconnect with backoff, listeners and routes replayed

**MITM proxy**

* Full TLS interception, leaf certificates signed on the fly and cached
* HTTP/1.1, HTTP/2 and cleartext h2c, with ALPN mirrored from the real upstream and translated on mismatch
* gRPC with trailers, SSE streamed event by event, gzip correct whether or not the client asked for it
* WebSocket spliced, not re-terminated — subprotocol, `permessage-deflate` and fragmentation intact
* Routes: your `http.Handler` in-process, another target, a raw pipe, or a refusal — with per-domain header injection, `tls://` / `h2c://` / `http://` targets, SNI override and wildcards
* Middleware on every terminated request — read or rewrite bodies, SSE and WebSocket frames
* Automatic passthrough for pinning and mTLS upstreams
* Works standalone, with no tunnel at all

```
 SANDBOX / CONTAINER             CONTROLPLANE (your machine)

┌───────────────────────┐        ┌────────────────────────────────────┐
│ AI agent / dev tools  │        │ vtunnel client                     │
│        │              │        │   + MITM proxy                     │
│        ▼              │ TUNNEL │   + CA private key                 │
│ HTTPS_PROXY=:9090     │◀══════▶│   + credentials                    │
│        │              │        │      │                             │
│ vtunnel server :3001  │        │      ├─ api.anthropic.com          │
│   + egress :9090      │        │      │    inject key ──▶ anthropic │
│                       │        │      │                             │
│ routes by domain,     │        │      ├─ github.com                 │
│ never decrypts:       │        │      │    inject PAT ──▶ github    │
│ no CA, no secrets     │        │      │                             │
│                       │        │      └─ nexus.corp                 │
│ unmapped ──▶ internet │        │           passthrough ──▶ nexus    │
└───────────────────────┘        └────────────────────────────────────┘
```

Mapped domains go through the tunnel. Everything else egresses from the sandbox directly.

One binary, two pieces — **[the tunnel](#the-tunnel)** and **[the MITM proxy](#the-mitm-proxy)** — documented separately below, because neither needs the other.

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Install](#install)
- [**The tunnel**](#the-tunnel)
  - [How it works](#how-it-works)
  - [Sandbox side](#sandbox-side)
  - [Controlplane side](#controlplane-side)
  - [Authentication](#authentication)
  - [Transports](#transports)
  - [Session protocols](#session-protocols)
  - [Raw port forwards](#raw-port-forwards)
  - [SOCKS5](#socks5)
  - [Egress policy](#egress-policy)
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
vtunnel server -listen ws://:3001/ -proxy 9090
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

Upgrading from 0.6.x? Interception moved out of the sandbox, the tunnel keypair became a shared secret, and the wire protocol changed — see [MIGRATING.md](MIGRATING.md).

---

# The tunnel

## How it works

Three layers, each replaceable without touching the others:

| layer | what it does | choices |
|---|---|---|
| **transport** | carries bytes, produces a `net.Conn` | `ws`, `wss`, `tcp` |
| **session** | multiplexes streams, authenticates both ends | `ssh`, `yamux` |
| **tunnel** | opens ports, routes by domain, pipes | [`server.go`](server.go), [`client.go`](client.go) |

Which makes four parts to assemble, and each is usable on its own:

| part | where | what it is |
|---|---|---|
| [`EgressProxy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#EgressProxy) | sandbox | the proxy the application points `HTTPS_PROXY` at; decides deny, direct, or through the tunnel |
| [`Listen`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Listen) | sandbox | the accepting half of the transport, a plain `net.Listener` |
| [`NewDialer`](https://pkg.go.dev/github.com/vivid-money/vtunnel#NewDialer) | controlplane | the dialling half, and where a proxy or a retry is wrapped in |
| [`MITMProxy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy) | controlplane | the CA, the real targets and the injected credentials |

The two proxies are the useful ones to take on their own: `MITMProxy` as an intercepting forward proxy and `EgressProxy` as an allowlisting one, with no tunnel involved either way. See [Using it without a tunnel](#using-it-without-a-tunnel).

The split is worth stating because it decides where security lives: **the session authenticates, always, and the transport contributes nothing.** Running over `wss://` proves nothing about who is on the other end — a TLS endpoint is whoever holds a certificate for that name, and that is not the same question as whether the peer knows this tunnel's secret. So `ws://` and `tcp://` are exactly as safe as `wss://`, and picking between them is a networking decision.

Above the session sits one small protocol ([`protocol.go`](protocol.go)): every stream opens with a length-prefixed JSON header saying what it is for, and a control stream reads one reply back. That is deliberately not built out of SSH channel types and global requests, which a multiplexer like yamux does not have — written above the session instead, it is written once for every backend.

**The client dials in.** A [`Server`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Server) runs inside the sandbox and accepts connections; a [`Client`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Client) runs on your machine and connects to it. The sandbox therefore needs no route back out to you, and no inbound port beyond the one the tunnel arrives on.

**The two sides are deliberately unequal.** The [`EgressProxy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#EgressProxy) in the sandbox ([`egress.go`](egress.go)) holds domain names and, if you give it any, egress rules — no CA, no credentials. It reads the domain from the `CONNECT` request line, which the application sends in cleartext before any TLS, and then either chains the connection to the controlplane, dials it directly, or refuses it. It cannot decrypt.

**Only domain names and the sandbox's own egress rules cross the tunnel.** Targets, injected headers and the CA private key never do. A rule and a target look similar from a distance and are not the same thing: a rule says what this sandbox may reach, which the sandbox is the one enforcing and could discover by trying; a target says where a name really goes on the controlplane's network, which the sandbox has no way to learn and no business holding.

## Sandbox side

```bash
vtunnel server -listen ws://:3001/ -proxy 9090
```

The server takes no CA: it cannot intercept TLS by design. Over `ws`, `/health` returns `ok` for health checks.

As a library, when the tunnel is all this process serves:

```go
server := vtunnel.NewServer(vtunnel.WithServerSecret(secret))
server.StartProxy("127.0.0.1:9090") // the application's HTTPS_PROXY

ln, err := vtunnel.Listen("ws://:3001/") // or tcp://:3001
if err != nil {
    log.Fatal(err)
}
log.Fatal(vtunnel.Serve(ln, server))
```

To share a port with your own HTTP handlers instead — a health endpoint, a metrics scrape — upgrade the request yourself and hand the connection over:

```go
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        return
    }
    defer conn.Close()
    server.HandleWebSocket(conn)
})
http.ListenAndServe(":3001", nil)
```

[`Server.HandleConn`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Server.HandleConn) takes any `net.Conn`, so a transport of your own needs nothing more than an accept loop.

## Controlplane side

```bash
vtunnel client -server ws://container:3001/ -mitm-ca ca.pem -forward api.corp=localhost:8081
```

As a library — routes are declared on the proxy the client owns, and the client mirrors their domain names into the sandbox as they appear:

```go
ca, _ := vtunnel.LoadCA(pemBytes) // cert+key from ca.pem; the key stays here

client := vtunnel.NewClient("ws://sandbox:3001/",
    vtunnel.WithSecret(secret),
    vtunnel.WithMitm(ca),
)
client.Connect()
defer client.Close()

client.Proxy().ForwardTo("api.corp", "localhost:8081",
    vtunnel.WithHeader("Authorization", "Bearer "+token))
```

Routes may be changed at any time while connected. Each change re-sends the full domain list, which the sandbox applies wholesale; connections already established keep their old route until they are re-established.

## Authentication

One shared secret, the same string on both ends:

```bash
SECRET=$(openssl rand -base64 32)

vtunnel server -listen ws://:3001/ -secret "$SECRET"
vtunnel client -server ws://... -secret "$SECRET" -forward ...
```

There is no key format and nothing to generate with vtunnel — the secret is any string you find hard to guess. Whatever already mints secrets for you does fine: a per-sandbox UUID, a token out of a secret manager, 32 bytes from `openssl`.

From it both ed25519 identities are derived — the client's key and the server's host key — so the client proves itself *and* pins the peer's key, with nothing to exchange by hand. The secret goes through Argon2id first, which is what lets it be an ordinary string: whatever the session protocol, someone who can merely dial the sandbox ends up holding a value derived from the secret — SSH hands out the host public key during key exchange, and a TLS server sends its certificate to anyone who completes the handshake with it. Candidates can therefore always be tested offline, unthrottled, and Argon2id makes each of those guesses cost ~25 ms and 64 MiB.

**One per sandbox, passed at launch.** It is symmetric, so whoever holds it can be either end: a value baked into an image, or shared across a fleet, turns one compromised sandbox into the ability to pose as all of them. `-secret @/run/secrets/vtunnel` reads it from a file, which beats an argument visible in `ps`.

Nothing is refused. A short secret is taken and warned about, and no secret at all leaves the tunnel unauthenticated — both sides say so loudly at startup, and that warning is the only thing between that mode and production.

This is the tunnel's own authentication and has nothing to do with the MITM CA — see [The CA](#the-ca) for that.

## Transports

What carries the bytes. The scheme in the URL picks it, and both ends must agree:

| scheme | dial | listen | notes |
|---|---|---|---|
| `ws` | ✓ | ✓ | the default. Goes through firewalls and corporate HTTP proxies |
| `wss` | ✓ | — | terminate TLS in front and listen on `ws://` behind it |
| `tcp` | ✓ | ✓ | a raw socket: no WebSocket framing, no second encryption layer |

```bash
# sandbox                              # controlplane
vtunnel server -listen tcp://:3001     vtunnel client -server tcp://sandbox:3001 …
```

```go
ln, _ := vtunnel.Listen("tcp://:3001")
go vtunnel.Serve(ln, server)

client := vtunnel.NewClient("tcp://sandbox:3001", vtunnel.WithSecret(secret))
```

None of these is more secure than another — see [How it works](#how-it-works). Anything else is [`WithDialer`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithDialer) plus a `net.Listener` of your own; wrap [`NewDialer`](https://pkg.go.dev/github.com/vivid-money/vtunnel#NewDialer) to add behaviour the tunnel has no opinion about. Covered by [`vtunnel_protocol_test.go`](vtunnel_protocol_test.go).

## Session protocols

What multiplexes the streams and authenticates the two ends. There is no negotiation on purpose — a preamble exchanged before authentication is attack surface, and whoever deploys one end deploys the other — so a mismatch fails rather than falling back.

| `-protocol` | what it is | per-stream window |
|---|---|---|
| `ssh` | the default, `golang.org/x/crypto/ssh` | fixed at 2 MB |
| `yamux` | yamux over TLS 1.3, both ends' keys pinned to the secret | 8 MB, [tunable](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithStreamWindow) |
| `yamux-insecure` | the same with the TLS removed | 8 MB, tunable |

**The window is the reason there is a second one.** A stream cannot exceed window/RTT whatever the bandwidth, so `x/crypto/ssh`'s hard-coded 2 MB caps one connection at 40 MB/s against a sandbox 50 ms away — on any link, however fat. `yamux` makes that number a setting and defaults it to 8 MB. None of this shows up on loopback: it matters when the sandbox is far away, not when it is a container on the same host.

Allocation is a separate win and applies everywhere: `ssh` allocates more bytes than it carries, roughly a hundred times what `yamux` does for the same traffic.

Measure your own link with `go run ./cmd/bench -latency 50ms -window … -mode direct`.

**`yamux-insecure` has no encryption and no authentication**, and ignores the secret even when one is set. Whoever reaches the port owns the tunnel, and that includes every [`Client.Listen`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Client.Listen) target and the credential-injecting proxy behind it. It exists so the cost of the cryptography can be measured against the same code path without it — and the measurement says that cost is nothing once there is any latency to speak of, the two being indistinguishable at 50 ms. Both ends log a warning naming it, every time they start.

## Raw port forwards

Independent of all domain routing: the server opens a TCP port in the sandbox and pipes every connection to a local address, with no HTTP parsing and no interception.

```bash
-forward 9000=localhost:3000
-forward 8085=tls://www.google.com:443   # the client wraps the connection in TLS
```

```go
client.Listen(9000, "localhost:3000")
client.Listen(8085, "tls://www.google.com:443")   // no port means 443
```

The remote port has to be one you picked: something inside the sandbox is going to connect to it, and a port only the sandbox knows is a port nobody can use. `Listen(0, …)` is refused rather than accepted and quietly wired to nothing.

## SOCKS5

The routing proxy speaks SOCKS5 on the same port it speaks HTTP, so one address covers everything the sandbox runs:

```bash
export http_proxy=http://localhost:9090   # lower case matters, see below
export HTTP_PROXY=http://localhost:9090
export HTTPS_PROXY=http://localhost:9090
export ALL_PROXY=socks5h://localhost:9090
```

curl takes `http_proxy` in lower case only — [deliberately](https://everything.curl.dev/usingcurl/proxies/env.html), so that a CGI script cannot be handed a proxy by an incoming `Proxy:` header — and every other variable in either case. `ALL_PROXY` is the fallback for schemes with no variable of their own, which is what carries the non-HTTP traffic here. `NO_PROXY` still applies, and curl 7.86 and later match CIDR blocks in it.

It exists for the traffic that has no other way in — `psql`, `redis-cli`, `mongosh`, ssh, anything that never reads `HTTPS_PROXY`. Such a client used to leave the sandbox directly, past the allowlist and past the credential the controlplane would have injected, not by decision but because nothing asked it where it was going.

Nothing new crosses the tunnel: SOCKS5 only learns the destination, and the egress proxy then chains it as the same `CONNECT` an HTTPS client produces. The controlplane matches that name against its own routes and dials `ForwardTo`'s target, never an address from the wire — which is what keeps a compromised sandbox from using the tunnel as a door into the controlplane's network.

Two things follow from that, and both are deliberate:

**`socks5h`, not `socks5`.** The `h` leaves name resolution to the far side, so the name reaches the proxy and can be matched. A `socks5://` client resolves first and sends an address instead.

**An address nobody forwarded is refused** (`0x02 connection not allowed by ruleset`), rather than dialled. With no [egress policy](#egress-policy) there is nothing but names to match against, so allowing it would mean a client that resolves its own names slips past the allowlist without a word. Forward the address explicitly if it really is meant to be reachable:

```go
client.Proxy().ForwardTo("10.0.0.9:5432", "10.0.0.9:5432")
```

Set an egress policy and that blanket refusal is retired rather than added to: addresses are first-class once there are rules written in them, so a literal is judged by those rules — and judged the same way `CONNECT` judges it, which has accepted literals all along.

A non-HTTP target needs its port in the route, since a bare domain covers `:80` and `:443` only:

```go
client.Proxy().ForwardTo("db.corp:5432", "10.0.0.9:5432")
```

Only `CONNECT` is implemented. `BIND` and `UDP ASSOCIATE` are answered with `0x07 command not supported`, which is what mitmproxy answers too — a UDP association needs a datagram path the tunnel does not have, and refusing it up front lets a client fail immediately instead of waiting for something that is not coming.

## Egress policy

Everything above decides which domains go **through the tunnel**. What happens to the rest is a separate question, and by default the answer is "dial it" — right for a proxy whose job is routing, wrong for a sandbox somebody has been promised is contained.

A [`Policy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Policy) is how that changes. It is declared on the controlplane and enforced in the sandbox:

```go
client.SetEgressPolicy(vtunnel.Policy{
    Default: vtunnel.ActionDeny,
    Allow:   []string{"*.example.com", "10.0.0.0/8", "db.corp:5432"},
    Deny:    []string{"169.254.0.0/16"},
})
```

A rule is a CIDR, an address, a hostname or a wildcard hostname, each optionally carrying a port; without one it covers every port. Between two rules the more specific wins — an exact name or a single address beats a wildcard or a prefix, a longer suffix or prefix beats a shorter one, a rule naming a port beats one that does not — and on a tie, deny wins.

**Names are judged before resolution, addresses after it.** That split is the design. A name rule is the only thing that can be said about a name, and an address rule is about where the bytes actually go — so `Deny: ["169.254.0.0/16"]` holds even against a hostname pointing at cloud metadata, which is the case that matters. The address is checked from inside the dialler, on the address the kernel is about to connect to, so there is no window between checking and connecting for a name to change its answer in.

**Write a deny-all as `Default: ActionDeny`, not as `Deny: ["0.0.0.0/0"]`.** They are not the same and the difference is deliberate. A default is a backdrop an allowlist of names is written against; a `/0` deny rule is an explicit address deny, which outranks an allowed name and refuses everything. Keeping them distinct is what lets `Default: ActionDeny` + `Allow: ["*.example.com"]` and `Deny: ["169.254.0.0/16"]` both mean what they look like.

Three things are outside it, and worth knowing before relying on it:

- **A routed domain is not affected.** It does not egress from this sandbox at all — the controlplane dials it — so a route outranks every rule. `SetPolicy` logs a warning when a route contradicts one. What the controlplane dials on the sandbox's behalf is governed by the routes declared there and by [`HandleUnmapped`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.HandleUnmapped).
- **It is not a packet filter.** It sees what comes through the proxy. A process that ignores `HTTPS_PROXY` and opens its own socket is not covered, and cannot be without capabilities a container usually does not have.
- **Nothing here sees UDP**, DNS included.

A refusal answers `403` on HTTP and `0x02` on SOCKS5 — never a timeout, so "blocked" and "unreachable" stay distinguishable.

**Before the controlplane connects** the sandbox has no policy, and that window is real: a sandbox is serving as soon as its process is. [`WithServerEgressPolicy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithServerEgressPolicy), or `-default-egress deny` on the CLI, starts it closed instead, and whatever the controlplane later sends replaces it. It cannot lock the sandbox out of its own tunnel: the client dials in, and the hop to a tunnel port is exempt.

Covered by [`policy_test.go`](policy_test.go), [`egress_policy_test.go`](egress_policy_test.go) and [`egress_policy_e2e_test.go`](egress_policy_e2e_test.go).

## Reconnection

Automatic, with exponential backoff. Server-side listeners persist across reconnections, and forwards are replayed once the tunnel is back, so a dropped link recovers without intervention. Tunable with [`WithReconnectBackoff`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithReconnectBackoff) and [`WithKeepAlive`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithKeepAlive). Every reconnect redials through the same [`Dialer`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Dialer), so a transport with its own setup — handshake headers for a corporate proxy, a credential to refresh — gets it applied each time. Covered by [`vtunnel_reconnect_test.go`](vtunnel_reconnect_test.go).

---

# The MITM proxy

[`MITMProxy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy) ([`mitmproxy.go`](mitmproxy.go), [`mitm.go`](mitm.go)) is the side that decrypts, rewrites and talks to upstreams. Interception happens here, on the **controlplane**, never in the sandbox: the proxy signs short-lived leaf certificates on the fly from a CA that stays on your machine.

## Routes

A domain is served in exactly one of three shapes. Which one you pick decides what is possible with it.

| | What happens | Needs a CA | Can inject headers |
|---|---|---|---|
| [`ForwardTo(domain, target)`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.ForwardTo) | TLS is terminated and the request re-issued to `target` | yes | **yes** |
| [`Handle(domain, h)`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.Handle) | served by your `http.Handler` in this process; no upstream connection at all | yes | n/a |
| [`Forward(domain)`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.Forward) | the target is the host the client asked for, filled in per request | no | no |

They differ in **where** the request goes, not in whether it is decrypted. With a CA configured, everything routed through this proxy is intercepted — including `Forward`, whose target is simply the authority the client named. Without one nothing can be, so `Forward` is piped and `ForwardTo` degrades to a pipe aimed at its target.

The way out of interception is [`MITMExceptions`](#when-interception-cannot-work), which is also what the proxy records for itself after a handshake that could not have worked. Reach for it when the client pins certificates, or when what rides inside the TLS is not HTTP.

`Forward` is the only shape a wildcard can carry: its target comes from the request, so `*.corp` sends every host under it to itself, where a fixed target would send them all to one place.

Anything in the "needs a CA" column is **refused when no CA is configured**, at the point the route is declared rather than on every request that reaches it. Injection happens after TLS is terminated, so on a proxy that cannot terminate it a route carrying headers would answer requests perfectly normally and simply never add the credential — a failure with no error to see. A CA-less proxy is still fully useful for routing and passthrough; it just cannot promise what it cannot do.

Anything with no route is dialled directly. [`HandleUnmapped`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.HandleUnmapped) changes that — a controlplane proxy usually wants to refuse, so a compromised tunnel cannot turn it into an open relay:

```go
proxy.HandleUnmapped(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    http.Error(w, "unknown domain", http.StatusForbidden)
}))
```

How to reach the target can be stated, or left to be discovered:

| target | the hop to the upstream |
|---|---|
| `localhost:8080` | asked about, if the route injects a header |
| `tls://host:port` | TLS, SNI from the host — a bare `:443` says the same |
| `h2c://host:port` | cleartext HTTP/2, nothing probed for it |
| `http://host:port` | cleartext, and do not ask |

[`WithSNI`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithSNI) overrides the name presented in the handshake, for a certificate issued for something the address does not carry; it contradicts `h2c://` and is refused with it. A domain given without a port registers on both `:80` and `:443`.

Discovery is the right default for an address somebody typed, and it costs something. An unstated scheme on a route that injects a credential is probed before the first request, because writing the credential to find out is exactly what must not happen — and an upstream that answers neither way is refused rather than guessed at. h2c is only ever looked for when the client side is HTTP/2 too, so an h2c-only upstream behind an HTTP/1.1 client is reachable by saying `h2c://` and not otherwise ([`mitmproxy_h2c_target_test.go`](mitmproxy_h2c_target_test.go), [`mitmproxy_upstream_scheme_test.go`](mitmproxy_upstream_scheme_test.go)).

## Wildcard domains

One entry matches a family of hostnames. The same matcher serves both sides of the tunnel ([`proxyshared.go`](proxyshared.go)), so a host resolves identically in the sandbox and on the controlplane.

```bash
-forward '*.example.test=localhost:8080'   # all subdomains
-forward 'mail.*=localhost:8080'           # all hosts starting with mail.
```

- `*` must be a **complete label on a dot border**, either leftmost (`*.example.test`) or rightmost (`mail.*`). Middle or partial-label asterisks (`a.*.b`, `w*.example.test`) are literal strings.
- Matches **one or more** extra labels: `*.example.test` matches `a.example.test` and `a.b.example.test`, but not the apex `example.test`.
- **Priority**: exact beats wildcard; leftmost beats rightmost; within a group, the longer pattern wins.

Covered by [`mitmproxy_wildcard_test.go`](mitmproxy_wildcard_test.go).

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
ENV http_proxy=http://localhost:9090
ENV HTTP_PROXY=http://localhost:9090
ENV HTTPS_PROXY=http://localhost:9090
ENV ALL_PROXY=socks5h://localhost:9090
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

**ALPN is mirrored, not guessed.** The proxy establishes the upstream connection before finishing the client's handshake, so the protocol it offers the application is one the upstream actually supports. When the client's ALPN excludes what the upstream settled on, the proxy translates between the two instead of failing the handshake — it re-issues requests rather than piping them, so the two sides need not agree ([`mitmproxy_alpn_mirror_test.go`](mitmproxy_alpn_mirror_test.go)).

**gRPC works, trailers included.** `grpc-status` arrives after the body, so it is forwarded separately from the headers; unannounced trailers are handled too ([`mitmproxy_trailers_test.go`](mitmproxy_trailers_test.go), [`mitmproxy_grpcurl_test.go`](mitmproxy_grpcurl_test.go)). Cleartext h2c over `CONNECT` is terminated without a certificate, which is what makes header injection into plain gRPC possible ([`mitmproxy_h2c_connect_test.go`](mitmproxy_h2c_connect_test.go)).

**Compression passes through correctly.** If the application asked for `gzip`, the compressed bytes are forwarded untouched with `Content-Encoding` intact. If it did not, the proxy's own transport asks for compression, decompresses, and drops the header — so the body and the headers describing it always agree ([`mitmproxy_gzip_test.go`](mitmproxy_gzip_test.go)).

## Streaming responses

Server-sent events are delivered event by event, not batched at end-of-body — an agent that depends on incremental `text/event-stream` from an LLM API behaves as if the response arrived empty otherwise. Every path the proxy can serve a route on has its own copy loop, and all of them are covered: HTTP/1.1, HTTP/2, an h2 client against an HTTP/1.1 upstream, a `tls://` upstream, an in-process handler, a raw pipe and plain HTTP ([`mitmproxy_sse_test.go`](mitmproxy_sse_test.go)).

Streaming survives compression and header injection too.

## WebSocket and other upgrades

Upgrades are **spliced, not re-terminated**. The handshake is re-issued as an ordinary request, so headers configured for the route land inside it; once the upstream answers `101`, the two connections are joined and nothing further is parsed.

That is what keeps the negotiation between the endpoints: **subprotocols, `permessage-deflate` and frame boundaries survive exactly as agreed**. A proxy that terminates the WebSocket in the middle has to re-negotiate both and in practice drops compression.

Works on every route shape and on both transports — `wss` through `CONNECT`, and cleartext `ws://` through the sandbox egress proxy, which cannot use an ordinary HTTP transport because it has no way to return a `101`. Covered by [`mitmproxy_websocket_test.go`](mitmproxy_websocket_test.go); see [`ExampleMITMProxy_ForwardTo_webSocket`](example_test.go).

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

This is the only way out, which is deliberate: a proxy holding a CA intercepts everything routed through it, so "leave this one alone" is something you say rather than something you get by spelling a route differently.

Two cases deliberately keep failing instead:

- a forward carrying `-H`, because a request that quietly kept working without its credential would hide the problem rather than report it;
- a domain served in-process, which has no upstream to fall back to.

Domains known to pin can be declared up front, so not even the first request is spent discovering it:

```go
proxy.MITMExceptions("pinned.example.com")
```

Covered by [`mitmproxy_exceptions_test.go`](mitmproxy_exceptions_test.go); see [`ExampleMITMProxy_MITMExceptions`](example_test.go).

**HTTP/3 is a different escape.** Interception here is about TCP; QUIC is UDP, and neither this proxy nor the tunnel carries it. An upstream that answers with `Alt-Svc: h3=":443"` is inviting the client to come back over UDP, straight past everything described above — so the header is stripped from every response the proxy passes on, which is what mitmproxy's own `update_alt_svc` addon exists for (it rewrites the header to point at itself; having no h3 port to name, we drop it). That leaves the case of a client told about HTTP/3 by some other means, and the answer to that one is the sandbox's firewall: if outbound UDP/443 is open, traffic can leave that way regardless of what any proxy says.

## Shutting down

[`Close`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.Close) stops immediately: the listener goes down and every connection still open is dropped, including `CONNECT` tunnels and the servers running on top of them.

[`Shutdown(ctx)`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.Shutdown) lets requests already in flight finish first, and gives up at the deadline. A byte pipe and an open stream have no request boundary to wait for, so those are only ever ended by the deadline — give the context a bound you are willing to wait for.

Either way the teardown reaches **past the proxy**: closing the client connection cancels the handler's request context, which aborts the upstream round trip and closes its body, so a streaming upstream stops streaming instead of billing for tokens nobody reads ([`mitmproxy_shutdown_test.go`](mitmproxy_shutdown_test.go)).

On the sandbox side, [`Server.Close`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Server.Close) releases everything the server owns: every forwarded port and its accept loop, the routing proxy, and the client session being served. Those ports deliberately outlive any one client connection, so that a reconnecting client finds them still open — which makes `Close` the only thing that ends them.

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

`EgressProxy` stands on its own too, as the other half of the same idea: no CA, no interception, just an allowlisting forward proxy on HTTP and SOCKS5. A `Server` with no tunnel attached is the way to reach one:

```go
sandbox := vtunnel.NewServer(vtunnel.WithServerEgressPolicy(vtunnel.Policy{
    Default: vtunnel.ActionDeny,
    Allow:   []string{"*.example.com"},
}))
sandbox.StartProxy("127.0.0.1:9090")
defer sandbox.Close()
```

Nothing dials in, no client exists, and the rules apply from the first connection. `sandbox.Egress()` reaches the proxy itself, for `SetPolicy` and `SetRoutes` at runtime.

---

## CLI reference

### `vtunnel server`

| Flag | Description | Default |
|------|-------------|---------|
| `-listen` | Where to accept the tunnel: `ws://:3001/` (also serves `/health`) or `tcp://:3001` | `$VTUNNEL_LISTEN`, else `ws://:3001/` |
| `-proxy` | Where the routing proxy listens, serving HTTP and SOCKS5 on one port: `9090` (loopback), `127.0.0.1:9090`, `:9090` for every interface, or a scheme in front of a full `host:port` to pick the front ends — `mixed://` (both, the default), `http://127.0.0.1:8080`, `socks5://127.0.0.1:1080`. A scheme does not carry the bare-port shorthand or its loopback default: `socks5://1080` is an error, `socks5://:1080` is every interface. SOCKS5 clients want `socks5h://`, see [SOCKS5](#socks5). Empty disables it. It authenticates nobody, so keep it on loopback unless something else guards the port | `$VTUNNEL_PROXY`, else empty |
| `-secret` | Shared tunnel secret, or `@/path` to a file | `$VTUNNEL_SECRET` |
| `-protocol` | Session protocol: `ssh`, `yamux`, `yamux-insecure`. Must match the client | `$VTUNNEL_PROTOCOL`, else `ssh` |
| `-default-egress` | What happens to a destination no rule names: `allow` or `deny`. See [Egress policy](#egress-policy) | `$VTUNNEL_DEFAULT_EGRESS`, else `allow` |
| `-allow-out` | Permit a CIDR, address, hostname or `*.hostname`, optionally `:port` (repeatable) | — |
| `-deny-out` | Refuse one, same syntax (repeatable) | — |

### `vtunnel client`

| Flag | Description | Default |
|------|-------------|---------|
| `-server` | Tunnel URL; the scheme picks the transport (required) | — |
| `-secret` | Shared tunnel secret, or `@/path` to a file | `$VTUNNEL_SECRET` |
| `-protocol` | Session protocol: `ssh`, `yamux`, `yamux-insecure`. Must match the sandbox | `$VTUNNEL_PROTOCOL`, else `ssh` |
| `-mitm-ca` | PEM with CA cert+key for HTTPS MITM; created if missing. Without it TLS is piped through untouched and `-H` is rejected | `$VTUNNEL_MITM_CA` (unset = no interception) |
| `-forward` | Forward mapping (repeatable, at least one required) | — |
| `-H` / `-header` | Header injected into requests for the preceding `-forward` (repeatable) | — |
| `-default-egress` | What happens to a destination no rule names: `allow` or `deny`. See [Egress policy](#egress-policy) | `$VTUNNEL_DEFAULT_EGRESS`, else `allow` |
| `-allow-out` | Permit a CIDR, address, hostname or `*.hostname`, optionally `:port` (repeatable) | — |
| `-deny-out` | Refuse one, same syntax (repeatable) | — |

### `vtunnel ca`

| Flag | Description | Default |
|------|-------------|---------|
| `-mitm-ca` | PEM with CA cert+key (created if missing) | `$VTUNNEL_MITM_CA`, else `ca.pem` |
| `-out` | Where to write the certificate | alongside the CA, as `.crt` |
| `-stdout` | Print the certificate instead of writing a file | `false` |

### `-forward` formats

```bash
# No target: go to whatever host was asked for. Intercepted like any other
# route when -mitm-ca is given. -H does not apply — attach headers to the
# target form below.
-forward gitlab.corp

# Intercepted and re-issued to the real host — the form to use when you want
# headers injected into it.
-forward gitlab.corp=gitlab.corp:443

# Route to a service on the controlplane
-forward myapi.local=localhost:8080

# State how to reach the target instead of leaving it to be discovered. The
# client terminates the application's TLS and opens this second hop itself,
# so the two legs are independent and only this one needs a scheme.
-forward myapi.local=tls://api.example.com:443   # TLS, SNI from the host
-forward grpc.corp=h2c://api.internal:13002      # cleartext HTTP/2, nothing probed
-forward legacy.corp=http://api.internal:8080    # cleartext, no TLS probe

# Wildcards
-forward '*.example.test=localhost:8080'
-forward 'mail.*=localhost:8080'

# Port forward: the server opens a TCP port and tunnels every connection.
# tls:// is the client wrapping that pipe; a raw pipe parses nothing, so no
# other scheme means anything here.
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

### Client options

Passed to [`NewClient`](https://pkg.go.dev/github.com/vivid-money/vtunnel#NewClient).

| Option | What it does | Default |
|---|---|---|
| [`WithSecret`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithSecret) | The shared tunnel secret; see [Authentication](#authentication) | none — unauthenticated, and warned about |
| [`WithProtocol`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithProtocol) | How streams are multiplexed and both ends authenticated. A sandbox set to anything else refuses the connection | `ssh` |
| [`WithDialer`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithDialer) | A transport of your own, and where transport-shaped settings live — WebSocket handshake headers among them | from the URL scheme |
| [`WithStreamWindow`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithStreamWindow) | How much the sandbox may send into one connection before this end acknowledges it — a speed limit, see [Session protocols](#session-protocols). Ignored by `ssh` | 8 MB |
| [`WithMitm`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithMitm) | Turn on TLS interception with this CA | off — TLS piped through untouched |
| [`WithProxy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithProxy) | Supply the controlplane proxy yourself, to share one between clients or pin its address | one is created |
| [`WithKeepAlive`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithKeepAlive) | Ping interval; negative disables | 30s |
| [`WithReconnectBackoff`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithReconnectBackoff) | Reconnect backoff window | 1s → 5s |

[`WithPingInterval`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithPingInterval) is a deprecated alias for `WithKeepAlive`. Headers for the WebSocket handshake — a corporate proxy wanting `Proxy-Authorization`, say — belong to the WebSocket rather than to the tunnel, so they go on the dialer:

```go
d, _ := vtunnel.NewDialer("wss://sandbox:3001/", http.Header{
    "Proxy-Authorization": {"Basic " + creds},
})
client := vtunnel.NewClient("wss://sandbox:3001/", vtunnel.WithDialer(d), vtunnel.WithSecret(secret))
```

### Server options

Passed to [`NewServer`](https://pkg.go.dev/github.com/vivid-money/vtunnel#NewServer). Each mirrors a client option, and the pair must agree.

| Option | What it does | Default |
|---|---|---|
| [`WithServerSecret`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithServerSecret) | The same secret the client is given | none — unauthenticated, and warned about |
| [`WithServerProtocol`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithServerProtocol) | How streams are multiplexed and both ends authenticated. A client set to anything else is refused | `ssh` |
| [`WithServerStreamWindow`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithServerStreamWindow) | The same thing for the other direction: how much the controlplane may send into one connection before the sandbox acknowledges it | 8 MB |
| [`WithServerEgressPolicy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithServerEgressPolicy) | Egress rules in force from startup, for the window before a controlplane connects; see [Egress policy](#egress-policy) | none — anything unrouted is dialled |
| [`WithServerKeepAlive`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithServerKeepAlive) | Ping interval | 30s |

One client at a time: a second connection takes the tunnel over and the previous session is closed, with a line in the log. Refusing it instead would lock a client out of its own sandbox after a half-open connection, which nothing notices until the keepalive does.

The two stream windows are independent, so raising one raises one — and the worst case is memory, since a stalled target can leave a window's worth buffered for every connection open at the time.

### Route options

Passed to [`MITMProxy.ForwardTo`](https://pkg.go.dev/github.com/vivid-money/vtunnel#MITMProxy.ForwardTo) and its siblings: [`WithHeader`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithHeader) injects a header into every request for the domain, [`WithSNI`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithSNI) sets the server name the proxy presents upstream. Proxy construction takes [`WithMitmCA`](https://pkg.go.dev/github.com/vivid-money/vtunnel#WithMitmCA); see [Using it without a tunnel](#using-it-without-a-tunnel).

See [pkg.go.dev](https://pkg.go.dev/github.com/vivid-money/vtunnel).

## License

MIT
