// Package vtunnel routes traffic out of a sandbox through a reverse tunnel,
// so that credentials and TLS interception stay on a machine the sandbox
// cannot reach.
//
// # Two sides
//
// A [Server] runs inside the sandbox. A [Client] runs on the controlplane —
// your machine — and dials it. Because the client dials in, the sandbox needs
// no route back out to you.
//
// # Three layers
//
// The tunnel is a transport, a session and the tunnel proper, and each is
// chosen independently:
//
//   - The transport carries bytes and produces a net.Conn. The URL scheme
//     picks it — ws, wss or tcp — for both [NewClient] and [Listen], and
//     [WithDialer] covers anything else.
//   - The session multiplexes streams over that connection and authenticates
//     both ends. [WithProtocol] picks it; see [Protocol].
//   - The tunnel opens ports in the sandbox, routes by domain and pipes.
//
// Authentication is the session's job and only the session's job. The
// transport contributes nothing to it: wss:// proves that the far end holds a
// certificate for a name, which is not the question of whether it knows this
// tunnel's secret. So ws://, wss:// and tcp:// are equally safe, and choosing
// between them is a networking decision.
//
// Each side owns a proxy, and they are deliberately unequal:
//
//   - [Router], inside the sandbox, is reachable as the application's
//     HTTPS_PROXY. It holds a list of domain names and nothing else. It never
//     terminates TLS: it takes the domain from the cleartext CONNECT request
//     line, and either chains the request through the tunnel or dials it
//     directly.
//   - [MITMProxy], on the controlplane, holds the real targets, the injected
//     headers and the MITM CA. It is what actually decrypts, rewrites and
//     talks to upstreams.
//
// Only domain names cross the tunnel. Targets, headers and the CA private key
// never do.
//
// [MITMProxy] depends on neither [Server] nor [Client]. Given a CA and a listen
// address it is a complete intercepting forward proxy on its own, with no
// tunnel anywhere in sight — useful for local development and tests, where the
// "sandbox" is another process on the same host.
//
// # Sandbox side
//
//	server := vtunnel.NewServer(vtunnel.WithServerSecret(secret))
//	server.StartProxy("127.0.0.1:9090") // the application's HTTPS_PROXY and ALL_PROXY
//
//	ln, err := vtunnel.Listen("ws://:3001/") // or tcp://:3001
//	if err != nil {
//	    log.Fatal(err)
//	}
//	log.Fatal(vtunnel.Serve(ln, server))
//
// [Server.Close] releases the lot: forwarded ports, their accept loops, the
// routing proxy and the session being served. Forwarded ports outlive any one
// client connection on purpose, so nothing else ends them.
//
// To share the port with handlers of your own — a health endpoint, a metrics
// scrape — upgrade the request yourself and hand the connection over:
//
//	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
//	    conn, err := upgrader.Upgrade(w, r, nil)
//	    if err != nil {
//	        return
//	    }
//	    defer conn.Close()
//	    server.HandleWebSocket(conn)
//	})
//	http.ListenAndServe(":3001", nil)
//
// [Server.HandleConn] takes any net.Conn, so a transport of your own needs
// nothing beyond an accept loop.
//
// # Controlplane side
//
//	ca, _ := vtunnel.LoadCA(pemBytes) // cert+key from ca.pem; the key stays here
//
//	client := vtunnel.NewClient("ws://sandbox:3001/",
//	    vtunnel.WithSecret(secret),
//	    vtunnel.WithMitm(ca),
//	)
//	client.Connect()
//	defer client.Close()
//
//	// Routes are declared on the proxy the client owns; the client mirrors
//	// their domain names into the sandbox as they appear.
//	routes := client.Proxy()
//
//	// Reach a private service, injecting a credential the sandbox never sees.
//	routes.ForwardTo("api.corp", "localhost:8081",
//	    vtunnel.WithHeader("Authorization", "Bearer "+token))
//
//	// Route it to itself with its TLS untouched — the only shape that works
//	// against an upstream that pins certificates, and the one that cannot
//	// carry an injected header.
//	routes.Forward("gitlab.corp")
//
// [MITMProxy.ForwardTo], [MITMProxy.Handle], [MITMProxy.Forward] and
// [MITMProxy.Remove] may be called at any time while connected; each call
// re-sends the full domain list, which the router applies wholesale.
// Connections already established keep their old route until they are
// re-established.
//
// Interception happens exactly when [WithMitm] is given. Without it the client
// still forwards domains, but their TLS is piped through untouched and
// [WithHeader] has nothing to inject into.
//
// For the CA itself, [GenerateCA] produces a cert+key blob and [CACertPEM]
// extracts the certificate half — the only part that belongs in a sandbox
// trust store.
//
// The routing proxy serves HTTP and SOCKS5 on that one port. SOCKS5 is there
// for what does not read HTTPS_PROXY — psql, redis-cli, ssh — and adds nothing
// to what crosses the tunnel: it learns a destination and chains the same
// CONNECT an HTTPS client would. Point ALL_PROXY at it as socks5h, so names
// reach the proxy unresolved; an address nobody forwarded is refused, because
// an allowlist written in names cannot match one.
//
// # Raw port forwards
//
// [Client.Listen] is independent of all the above: it asks the server to open
// a TCP port in the sandbox and pipes every connection to a local address, with
// no HTTP parsing. A "tls://" prefix on the target makes the client wrap the
// connection in TLS, on port 443 unless another is given. The remote port must
// be one you chose — something in the sandbox has to be told where to connect.
//
//	client.Listen(9000, "localhost:3000")
//	client.Listen(8085, "tls://www.google.com:443")
//
// # Migrating
//
// 1.0 moved TLS interception out of the sandbox, replaced the tunnel keypair
// with one shared secret — [WithSecret] and [WithServerSecret] — and split the
// transport from the session. Both ends upgrade together; see MIGRATING.md for
// the details and for why every pre-1.0 keypair should be treated as
// compromised.
package vtunnel
