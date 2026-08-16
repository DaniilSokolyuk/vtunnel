# Example

## Controlplane + Sandbox

Run a container where all outbound HTTPS traffic is intercepted and credentials are injected outside the sandbox.

The controlplane returns mock responses ("Hello from mock!") so you can test the full flow without real API keys.

```
example/
├── sandbox/          # Container: vtunnel server + routing proxy, no CA key
│   ├── Dockerfile
│   └── entrypoint.sh
├── controlplane/     # Your machine: vtunnel client + MITM proxy + mock upstreams
│   └── src/index.ts
└── test.sh           # Builds, starts, tests, cleans up
```

```
 SANDBOX CONTAINER                  CONTROLPLANE (your machine)

┌────────────────────────┐        ┌──────────────────────────────────────────┐
│                        │        │ vtunnel client                           │
│ HTTPS_PROXY=:9090      │ TUNNEL │   + MITM proxy, CA private key           │
│      │                 │◀══════▶│      │                                   │
│ vtunnel server :3001   │        │      ├─ api.anthropic.com                │
│   + router :9090       │        │      │   inject API key ───▶ anthropic   │
│   + ca.crt (cert only) │        │      │                                   │
│                        │        │      ├─ github.com                       │
│ routes by domain,      │        │      │   inject PAT ───────▶ github      │
│ never decrypts         │        │      │                                   │
│                        │        │      └─ * unmapped ────────▶ direct      │
└────────────────────────┘        └──────────────────────────────────────────┘
```

The container holds only the CA **certificate**, so it can trust the interception
without being able to perform it. The private key and every credential stay on
the controlplane.

### Run

```bash
./example/test.sh
```

The sandbox image pulls a released `vtunnel` binary, and 0.7 changed the
configuration protocol — so this needs a published v0.7.0 to run against the
current source. Until then, point `VTUNNEL_VERSION` at a tag whose client you
also have locally, or build the binary into the image from this checkout.

The script builds the sandbox image, starts everything, runs tests from inside the container, and cleans up.

Expected output:

```
=== vtunnel example test ===

--- api.anthropic.com (should go through tunnel) ---
PASS api.anthropic.com routed through tunnel

--- github.com (should go through tunnel) ---
PASS github.com routed through tunnel

--- example.com (should go direct, not through tunnel) ---
PASS example.com went direct (HTTP 200)

=== All tests passed ===
```

### Manual run

One secret, the same string on both sides — the sandbox and the controlplane
authenticate each other with it, so generate it once and use it in both
terminals:

```bash
export VTUNNEL_SECRET=$(openssl rand -base64 32)
```

```bash
# Terminal 1: sandbox
cd example/sandbox
docker build -t vtunnel-sandbox .
docker run --rm -p 3001:3001 \
  -e VTUNNEL_SECRET="$VTUNNEL_SECRET" \
  vtunnel-sandbox

# Terminal 2: controlplane — same VTUNNEL_SECRET in the environment
cd example/controlplane
bun src/index.ts
```
