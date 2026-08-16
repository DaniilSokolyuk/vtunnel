# Migrating to 0.7

Coming from 0.6.x. TLS interception moved out of the sandbox: the private CA
key and the injected credentials now live only on the controlplane, and the
sandbox keeps a domain allowlist and a CA certificate.

**The wire protocol changed** — a 0.7 client cannot drive a 0.6 server, or the
reverse. Both sides upgrade together.

## Steps

**1. Generate the CA on the controlplane** (safe to do before upgrading — it
changes nothing yet):

```bash
vtunnel ca   # ca.pem stays here; ca.crt goes to the sandbox
```

Already have a CA you want to keep, so sandboxes need no new trust anchor? Put
its cert and key in one PEM and pass it as `-mitm-ca thatfile.pem` — to
`vtunnel ca` here, and to `vtunnel client` in step 3.

**2. Install `ca.crt` in the sandbox image** — the certificate only:

```dockerfile
COPY ca.crt /usr/local/share/ca-certificates/vtunnel-ca.crt
RUN update-ca-certificates
```

Delete whatever generated a CA inside the image. That key was the thing this
release exists to remove — treat it as compromised and stop using it.

**3. Upgrade both binaries and move the CA flag from server to client:**

```diff
 # in the sandbox
-vtunnel server -port 3001 -proxy 9090 -proxy-mitm-ca /etc/vtunnel-ca.pem
+vtunnel server -port 3001 -proxy 9090

 # on your machine
-vtunnel client -server ws://sandbox:3001/ -forward api.corp=localhost:8081 -H '...'
+vtunnel client -server ws://sandbox:3001/ -mitm-ca ca.pem \
+  -forward api.corp=localhost:8081 -H '...'
```

`-mitm-ca` is what turns interception on; the file is created if missing, so
step 1 and this flag name the same `ca.pem`. Omit it and TLS is piped through
untouched — in which case `-H` is rejected, because there is nothing to inject
into.

**4. Verify.** From inside the sandbox, a mapped domain should still work, and
the container should no longer hold a key:

```bash
curl https://api.corp/health           # works, credential injected outside
ls /etc/vtunnel-ca.pem                 # should not exist
```

`-forward`, `-H`, `-key` and `vtunnel keygen` are unchanged.

## API changes

Routes moved off `Client` and onto the proxy it owns, reached with
[`Client.Proxy`](https://pkg.go.dev/github.com/vivid-money/vtunnel#Client.Proxy).
The proxy no longer depends on the tunnel at all, which is what makes it usable
on its own — see [Using it without a tunnel](README.md#using-it-without-a-tunnel).

| Before (0.6) | Now (0.7) |
|---|---|
| `client.Forward(domain, target, opts...)` | `client.Proxy().ForwardTo(domain, target, opts...)` |
| `client.Unforward(domain)` | `client.Proxy().Remove(domain)` |
| `vtunnel.WithProxyMitmCA(cert)` — ServerOption | `vtunnel.WithMitm(cert)` — Option, on the client |
| `server.SetDomainMapping` / `SetDomainHeaders` | removed; routes arrive over the tunnel |
| `server.StartProxy` starts a MITM proxy | starts the routing proxy; interception is on the client |
| headers travelled to the sandbox in the listen request | headers never leave the controlplane |
| — | `vtunnel.GenerateCA` / `CACertPEM` / `LoadCA` |

`client.Listen` and `vtunnel.WithHeader` keep their signatures and behaviour.

`MITMProxy.Handle` and `MITMProxy.ForwardTo` now return an `error`. They use it
to refuse a route that could only be served by decrypting — an in-process
handler, or any route carrying injected headers — on a proxy with no CA. That
configuration used to be accepted and then quietly drop the credential on every
request. Check the error, or keep the CLI's shape and treat it as fatal:

```go
if err := client.Proxy().ForwardTo("api.corp", "localhost:8081",
    vtunnel.WithHeader("Authorization", "Bearer "+token)); err != nil {
    log.Fatal(err)
}
```

Rewriting a 0.6 call site is mechanical:

```diff
-client.Forward("api.corp", "localhost:8081",
-    vtunnel.WithHeader("Authorization", "Bearer "+token))
+client.Proxy().ForwardTo("api.corp", "localhost:8081",
+    vtunnel.WithHeader("Authorization", "Bearer "+token))
```

## Rollback

Downgrade both sides together. The 0.6 sandbox image needs its own CA back, so
keep the old image tag around until you are satisfied.
