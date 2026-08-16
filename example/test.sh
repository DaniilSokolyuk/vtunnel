#!/bin/bash
#
# End-to-end test for the controlplane + sandbox example.
# Builds, starts everything, runs curl FROM INSIDE the sandbox (where the
# MITM CA is trusted), verifies routing, cleans up.
#
# Usage: ./example/test.sh
#
set -e

cd "$(dirname "$0")"

GREEN='\033[0;32m'
RED='\033[0;31m'
DIM='\033[2m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $1"; }
fail() { echo -e "${RED}FAIL${NC} $1"; cleanup; exit 1; }
log()  { echo -e "${DIM}$1${NC}"; }

# Run curl inside the sandbox container (where the controlplane CA is trusted)
sandbox_curl() {
  docker exec vtunnel-test-sandbox \
    sh -c "HTTPS_PROXY=http://localhost:9090 curl -sf $*"
}

PIDS=()
cleanup() {
  log "cleaning up..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  docker rm -f vtunnel-test-sandbox 2>/dev/null || true
  [ -n "${CA_DIR:-}" ] && rm -rf "$CA_DIR"
}
trap cleanup EXIT

# --- Generate the tunnel secret ---
# One shared string, both ends. There is no key format; anything hard to guess
# works, and in production this comes from whatever creates the sandbox.
log "generating tunnel secret..."
VTUNNEL_SECRET=$(openssl rand -base64 32)
export VTUNNEL_SECRET

# --- Generate the MITM CA on THIS machine ---
# The private key never leaves the host; only the certificate is mounted.
log "generating MITM CA (private key stays here)..."
CA_DIR=$(mktemp -d)
export VTUNNEL_MITM_CA="$CA_DIR/ca.pem"
vtunnel ca -mitm-ca "$VTUNNEL_MITM_CA" -out "$CA_DIR/ca.crt" 2>/dev/null

# --- Build sandbox ---
log "building sandbox image..."
docker build -t vtunnel-test-sandbox sandbox/ -q

# --- Start sandbox ---
log "starting sandbox container..."
docker run --rm -d --name vtunnel-test-sandbox \
  -p 3001:3001 \
  -e VTUNNEL_SECRET="$VTUNNEL_SECRET" \
  -v "$CA_DIR/ca.crt:/etc/vtunnel-ca.crt:ro" \
  vtunnel-test-sandbox > /dev/null

log "waiting for vtunnel server..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:3001/health > /dev/null 2>&1; then
    break
  fi
  if [ "$i" = "30" ]; then
    fail "sandbox did not start in time"
  fi
  sleep 1
done

# --- Start controlplane ---
log "starting controlplane..."
(cd controlplane && bun src/index.ts) &
PIDS+=($!)

log "waiting for controlplane..."
for i in $(seq 1 15); do
  if curl -sf http://localhost:8081/ > /dev/null 2>&1 && \
     curl -sf http://localhost:8082/ > /dev/null 2>&1; then
    break
  fi
  if [ "$i" = "15" ]; then
    fail "controlplane did not start in time"
  fi
  sleep 1
done

# Give vtunnel client time to connect and register forwards
sleep 2

echo ""
echo "=== vtunnel example test ==="
echo ""

# --- Test 1: api.anthropic.com → tunnel → mock ---
echo "--- api.anthropic.com (should go through tunnel) ---"
RESP=$(sandbox_curl "https://api.anthropic.com/v1/messages" 2>&1) || true

if echo "$RESP" | grep -q "Hello from mock"; then
  pass "api.anthropic.com routed through tunnel"
else
  fail "api.anthropic.com not routed. Response: $RESP"
fi

echo ""

# --- Test 2: github.com → tunnel → mock ---
echo "--- github.com (should go through tunnel) ---"
RESP=$(sandbox_curl "https://github.com/test/repo" 2>&1) || true

if echo "$RESP" | grep -q "Hello from mock"; then
  pass "github.com routed through tunnel"
else
  fail "github.com not routed. Response: $RESP"
fi

echo ""

# --- Test 3: unmapped domain → direct ---
echo "--- example.com (should go direct, not through tunnel) ---"
CODE=$(sandbox_curl "-o /dev/null -w '%{http_code}' https://example.com" 2>&1) || true

if [ "$CODE" = "200" ]; then
  pass "example.com went direct (HTTP $CODE)"
else
  fail "example.com returned HTTP $CODE (expected 200)"
fi

echo ""
echo "=== All tests passed ==="
