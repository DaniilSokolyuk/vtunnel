#!/bin/sh
set -e

VTUNNEL_PORT=${VTUNNEL_PORT:-3001}
PROXY_PORT=${PROXY_PORT:-9090}

# Start vtunnel server with HTTPS proxy + MITM
exec vtunnel server \
  -port "$VTUNNEL_PORT" \
  -proxy "$PROXY_PORT" \
  -proxy-mitm-ca /etc/vtunnel-ca.pem \
  ${VTUNNEL_PUBLIC_KEY:+-client-key "$VTUNNEL_PUBLIC_KEY"}
