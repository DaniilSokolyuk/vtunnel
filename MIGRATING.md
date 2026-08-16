# Migrating to 0.8

Coming from 0.7.x. Tunnel authentication changed from a keypair to a single
shared secret, and **the old scheme did not authenticate the server at all** —
treat every existing `vt-pub-`/`vt-priv-` pair as compromised and replace it.

## Why

The server's SSH host key was derived from the client's *public* key:

```go
seed := sha256.Sum256(clientPublicKey.Marshal())   // 0.7, auth.go
```

That public key is published on purpose — it goes into sandbox images,
compose files, CI variables and the README. So anyone who read it could compute
the server's private host key, and `ssh.FixedHostKey` on the client verified
nothing: it proved only that the peer had read something that was never secret.

An attacker on the path of the client's `-server` URL could therefore pose as
the sandbox, and the tunnel then works in the attacker's favour by design. The
impostor opens `tunnel` channels; the client pipes each one into a local
address on the controlplane — the MITM proxy that injects credentials, and any
target passed to `Client.Listen`. See `TestImpostorWithoutTheSecretIsRefused`.

0.8 derives **both** identities from one shared secret that neither side
publishes:

```go
master     = Argon2id(secret)
clientSeed = HKDF(master, "vtunnel client key v1")
hostSeed   = HKDF(master, "vtunnel host key v1")
```

Both ends compute both keys, so one configured value still replaces a
distributed keypair — but now nobody else can compute either.

## Steps

**1. Get one secret per sandbox.** There is nothing to generate with vtunnel:
the secret is any string that is hard to guess, so use whatever already mints
secrets for you.

```bash
SECRET=$(openssl rand -base64 32)
```

Per sandbox, not one for the fleet. The secret is symmetric: whoever holds it
can be either end, so a shared one turns any single compromised sandbox into
the ability to pose as all of them.

**2. Pass it to both ends at launch:**

```diff
 # in the sandbox
-vtunnel server -port 3001 -proxy 9090 -client-key "vt-pub-…"
+vtunnel server -port 3001 -proxy 9090 -secret "$SECRET"

 # on your machine
-vtunnel client -server ws://sandbox:3001/ -key "vt-priv-…" …
+vtunnel client -server ws://sandbox:3001/ -secret "$SECRET" …
```

`$VTUNNEL_SECRET` works on both, and replaces `$VTUNNEL_CLIENT_KEY` and
`$VTUNNEL_KEY`. `-secret @/run/secrets/vtunnel` reads it from a file instead,
which is worth preferring — a command-line argument is visible in `ps` output
and lands in shell history.

**Never bake it into an image.** The whole point of the change is that the
sandbox now holds something secret; a value committed to a Dockerfile or a
compose file is exactly as public as `vt-pub-` was. Whatever creates the
sandbox should generate the secret, inject it as a runtime environment
variable, and hand the same value to the client that dials in.

**3. Verify.** Both ends log `Tunnel authentication enabled` at startup. If
either logs `WARNING: No tunnel secret configured`, that side is
unauthenticated and will accept or dial anything.

## API and CLI changes

| Before (0.7) | Now (0.8) |
|---|---|
| `vtunnel.GenerateKeyPair() (priv, pub string, err error)` | removed — a secret is any string |
| `vtunnel.WithClientKey(pub)` — ServerOption | `vtunnel.WithServerSecret(secret)` |
| `vtunnel.WithKey(priv)` — Option | `vtunnel.WithSecret(secret)` |
| `vtunnel keygen` | removed — use `openssl rand -base64 32` or your secret manager |
| `-client-key`, `$VTUNNEL_CLIENT_KEY` | `-secret`, `$VTUNNEL_SECRET` |
| `-key`, `$VTUNNEL_KEY` | `-secret`, `$VTUNNEL_SECRET` |

### What counts as a secret

Any string. There is no format to satisfy and no keypair to distribute,
because a format proves nothing about the one property that matters: that
nobody else can guess it. A per-sandbox UUID, a token from a secret manager,
`openssl rand -base64 32` — all fine.

**Nothing is refused.** A secret under 16 characters is accepted and warned
about; no secret at all leaves the tunnel unauthenticated, with a warning on
both sides. Failing to start would be worse than saying so.

Take the warning seriously, though. Guessing is cheap: SSH sends the host
public key in cleartext during key exchange, so anyone who can dial the sandbox
at all collects it and tests candidates offline, with no rate limit and nothing
to alert on. The secret is stretched with Argon2id (RFC 9106's second profile:
64 MiB, t=3, p=4) before the keys are derived, costing ~25 ms once at startup
and the same on every guess. That is worth roughly sixteen bits, and it is not
a substitute for entropy.

## Rollback

Downgrade both sides together and restore the old keypair — but the 0.7 scheme
authenticates only the client, so treat a rollback as running unauthenticated
in the server direction.

---

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
