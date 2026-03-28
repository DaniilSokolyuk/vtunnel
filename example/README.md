# Example

## Controlplane + Sandbox

Run a container where all outbound HTTPS traffic is intercepted and credentials are injected outside the sandbox.

The controlplane returns mock responses ("Hello from mock!") so you can test the full flow without real API keys.

```
example/
├── sandbox/          # Container: vtunnel server + MITM proxy
│   ├── Dockerfile
│   └── entrypoint.sh
├── controlplane/     # Your machine: vtunnel client + mock proxies
│   └── src/index.ts
└── test.sh           # Builds, starts, tests, cleans up
```

```
 SANDBOX CONTAINER                  CONTROLPLANE (your machine)

┌────────────────────────┐        ┌──────────────────────────────────────────┐
│                        │        │                                          │
│ HTTPS_PROXY=:9090      │ TUNNEL │ vtunnel client                           │
│      │                 │◀══════▶│      │                                   │
│ vtunnel server :3001   │        │      ├─ api.anthropic.com                │
│   + proxy :9090        │        │      │   inject API key ───▶ anthropic   │
│   + mitm ca.pem        │        │      │                                   │
│                        │        │      ├─ github.com                       │
│                        │        │      │   inject PAT ───────▶ github      │
│                        │        │      │                                   │
│                        │        │      └─ * unmapped ────────▶ direct      │
│                        │        │                                          │
└────────────────────────┘        └──────────────────────────────────────────┘
```

### Run

```bash
./example/test.sh
```

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

```bash
# Terminal 1: sandbox
cd example/sandbox
docker build -t vtunnel-sandbox .
docker run --rm -p 3001:3001 \
  -e VTUNNEL_PUBLIC_KEY="vt-pub-..." \
  vtunnel-sandbox

# Terminal 2: controlplane
cd example/controlplane
bun src/index.ts
```
