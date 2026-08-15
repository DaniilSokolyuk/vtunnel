#!/bin/sh
set -e

VTUNNEL_PORT=${VTUNNEL_PORT:-3001}
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
  -port "$VTUNNEL_PORT" \
  -proxy "$PROXY_PORT" \
  ${VTUNNEL_PUBLIC_KEY:+-client-key "$VTUNNEL_PUBLIC_KEY"}
