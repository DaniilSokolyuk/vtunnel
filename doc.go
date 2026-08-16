// Package vtunnel routes traffic out of a sandbox through a reverse tunnel,
// so that credentials and TLS interception stay on a machine the sandbox
// cannot reach.
//
// # Two sides
//
// A [Server] runs inside the sandbox. A [Client] runs on the controlplane —
// your machine — and dials the server over WebSocket, carrying SSH inside it
// for multiplexing, encryption and authentication. Because the client dials
// in, the sandbox needs no route back out to you.
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
//	server := vtunnel.NewServer(vtunnel.WithClientKey(publicKey))
//	server.StartProxy(":9090") // the application's HTTPS_PROXY
//
//	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
//	    conn, err := upgrader.Upgrade(w, r, nil)
//	    if err != nil {
//	        return
//	    }
//	    defer conn.Close()
//	    server.HandleConn(conn)
//	})
//	http.ListenAndServe(":3001", nil)
//
// # Controlplane side
//
//	ca, _ := vtunnel.LoadCA(pemBytes) // cert+key from ca.pem; the key stays here
//
//	client := vtunnel.NewClient("ws://sandbox:3001/",
//	    vtunnel.WithKey(privateKey),
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
// # Raw port forwards
//
// [Client.Listen] is independent of all the above: it asks the server to open
// a TCP port in the sandbox and pipes every connection to a local address, with
// no HTTP parsing. A "tls://" prefix on the target makes the client wrap the
// connection in TLS.
//
//	client.Listen(9000, "localhost:3000")
//	client.Listen(8085, "tls://www.google.com:443")
//
// # Migrating to 0.7
//
// Interception moved from the sandbox to the controlplane in 0.7, so the
// options moved with it:
//
//   - Server: WithProxyMitmCA is gone, and so is the -proxy-mitm-ca flag. The
//     server cannot intercept TLS at all now. Server.SetDomainMapping and
//     Server.SetDomainHeaders are gone too; routes arrive over the tunnel.
//   - Client: configure interception with [WithMitm]. Client.Forward and
//     Client.Unforward are gone; routes are declared on the proxy the client
//     owns, via [Client.Proxy], and configure that proxy instead of shipping
//     the target and headers into the sandbox.
//   - The listen request on the wire lost its LocalAddr and Headers fields.
//     A 0.7 client cannot drive a 0.6 server, or the reverse.
package vtunnel
