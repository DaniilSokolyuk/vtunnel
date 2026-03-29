# Sandbox container: vtunnel server + MITM proxy
#
# All outbound traffic goes through vtunnel's HTTPS proxy.
# The controlplane connects via vtunnel client and controls routing.

FROM debian:bookworm-slim

ARG VTUNNEL_VERSION=0.4.0
RUN apt-get update && apt-get install -y curl ca-certificates openssl && \
    curl -fsSL https://github.com/vivid-money/vtunnel/releases/download/v${VTUNNEL_VERSION}/vtunnel_${VTUNNEL_VERSION}_linux_amd64.tar.gz \
    | tar -xz -C /usr/local/bin vtunnel && \
    rm -rf /var/lib/apt/lists/*

# Generate MITM CA so the proxy can intercept HTTPS for domain forwards
RUN openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /etc/vtunnel-ca.pem -out /etc/vtunnel-ca.pem \
    -days 3650 -nodes -subj "/CN=vtunnel MITM CA" && \
    cp /etc/vtunnel-ca.pem /usr/local/share/ca-certificates/vtunnel-ca.crt && \
    update-ca-certificates

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3001 9090

ENTRYPOINT ["/entrypoint.sh"]
