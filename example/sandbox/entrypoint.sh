#!/bin/sh
set -e

# The scheme picks the transport. ws also serves /health, which is what the
# test script waits on; tcp:// would work just as well and just as safely.
VTUNNEL_LISTEN=${VTUNNEL_LISTEN:-ws://:3001/}
PROXY_PORT=${PROXY_PORT:-9090}

# Trust the controlplane's MITM CA certificate if one was mounted. Only the
# certificate ever reaches this container — never the private key.
CA_CERT=${CA_CERT:-/etc/vtunnel-ca.crt}
if [ -f "$CA_CERT" ]; then
  cp "$CA_CERT" /usr/local/share/ca-certificates/vtunnel-ca.crt
  update-ca-certificates >/dev/null
  echo "[entrypoint] trusted controlplane CA from $CA_CERT"
else
  echo "[entrypoint] WARNING: no CA at $CA_CERT; intercepted HTTPS will fail to verify"
fi

# Start vtunnel server: routing proxy only, no TLS interception here.
exec vtunnel server \
  -listen "$VTUNNEL_LISTEN" \
  -proxy "$PROXY_PORT" \
  ${VTUNNEL_SECRET:+-secret "$VTUNNEL_SECRET"}
