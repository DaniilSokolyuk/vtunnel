# Sandbox container: vtunnel server + routing proxy
#
# All outbound traffic goes through vtunnel's proxy, which routes by domain and
# never decrypts anything: TLS interception and credential injection happen on
# the controlplane, on the other side of the tunnel.

FROM debian:bookworm-slim

# Must match the controlplane: 0.7 changed the tunnel's configuration protocol,
# so a 0.6 binary on either side cannot talk to a 0.7 one.
ARG VTUNNEL_VERSION=0.7.0
RUN apt-get update && apt-get install -y curl ca-certificates && \
    curl -fsSL https://github.com/vivid-money/vtunnel/releases/download/v${VTUNNEL_VERSION}/vtunnel_${VTUNNEL_VERSION}_linux_amd64.tar.gz \
    | tar -xz -C /usr/local/bin vtunnel && \
    rm -rf /var/lib/apt/lists/*

# No CA is generated here. The MITM CA — private key included — belongs to the
# controlplane; this image only ever receives its certificate, mounted at run
# time and trusted by entrypoint.sh.

# Route everything through the routing proxy, and point every runtime's TLS
# stack at the one system bundle that entrypoint.sh adds the controlplane CA to.
# http_proxy is set in lower case as well as upper: curl accepts only the lower
# case one for plain HTTP, deliberately, so that a CGI script cannot be handed a
# proxy by an incoming Proxy: header. Everything else reads either.
ENV http_proxy=http://localhost:9090
ENV HTTP_PROXY=http://localhost:9090
ENV HTTPS_PROXY=http://localhost:9090
# socks5h, not socks5: the "h" keeps name resolution on the far side, so the
# domain reaches the proxy unresolved and can be matched against the allowlist.
# With socks5:// the client resolves first and sends an address, which matches
# no route by name and quietly egresses from the sandbox instead.
ENV ALL_PROXY=socks5h://localhost:9090
ENV NO_PROXY=localhost,127.0.0.1
ENV NODE_USE_ENV_PROXY=1
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt
ENV UV_SYSTEM_CERTS=true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Only the tunnel port is published. The routing proxy listens on loopback and
# is for processes inside this container: it authenticates nobody, and behind it
# are the controlplane's injected credentials.
EXPOSE 3001

ENTRYPOINT ["/entrypoint.sh"]
