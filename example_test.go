package vtunnel_test

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/websocket"

	"github.com/vivid-money/vtunnel"
)

// The sandbox side: a WebSocket endpoint for the controlplane to dial into, and
// a routing proxy for the application to point HTTPS_PROXY at. No CA and no
// credentials appear anywhere here — this side cannot decrypt.
func Example_sandbox() {
	server := vtunnel.NewServer(vtunnel.WithClientKey(os.Getenv("VTUNNEL_CLIENT_KEY")))

	if err := server.StartProxy(":9090"); err != nil {
		log.Fatal(err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		server.HandleConn(conn)
	})

	log.Fatal(http.ListenAndServe(":3001", nil))
}

// The controlplane side: dials into the sandbox and declares which domains it
// serves. The CA, the upstream addresses and the injected credentials all stay
// in this process.
func Example_controlplane() {
	caPEM, err := os.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	ca, err := vtunnel.LoadCA(caPEM)
	if err != nil {
		log.Fatal(err)
	}

	client := vtunnel.NewClient("ws://sandbox:3001/",
		vtunnel.WithKey(os.Getenv("VTUNNEL_KEY")),
		vtunnel.WithMitm(ca),
	)
	if err := client.Connect(); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Routes are declared on the proxy; the client mirrors their domains into
	// the sandbox as they appear.
	routes := client.Proxy()

	// A private service, reached with a credential the sandbox never receives.
	routes.ForwardTo("api.corp", "localhost:8081",
		vtunnel.WithHeader("Authorization", "Bearer "+os.Getenv("API_TOKEN")))

	// Served from this process — no upstream connection, no second proxy.
	routes.Handle("mock.corp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello from the controlplane")
	}))

	// Straight through to the real host: TLS is never terminated, so this works
	// even against an upstream that pins certificates.
	routes.Forward("gitlab.corp")

	// Every subdomain to one service.
	routes.ForwardTo("*.preview.corp", "localhost:8082")

	select {} // serve until killed
}

// Routes can be changed while connected: the sandbox is re-synced after every
// change, so nothing else has to be called.
func ExampleMITMProxy_Remove() {
	client := vtunnel.NewClient("ws://sandbox:3001/")
	if err := client.Connect(); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	client.Proxy().ForwardTo("api.corp", "localhost:8081")

	// Later: stop serving it. api.corp now egresses from the sandbox directly.
	client.Proxy().Remove("api.corp")
}

// Cross-cutting concerns — auth, audit, logging — attach once and wrap every
// request the proxy terminates, whether it is handled here or forwarded on.
func ExampleMITMProxy_Use() {
	proxy := vtunnel.NewMITMProxy()

	proxy.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %s%s", r.Method, r.Host, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	})

	// Refuse anything without a route, so a compromised sandbox cannot use this
	// as an open relay. The default is to dial the requested host directly.
	proxy.HandleUnmapped(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unknown domain", http.StatusForbidden)
	}))
}

// Raw TCP forwarding, with no HTTP or TLS handling: the server opens a port in
// the sandbox and pipes it to a local address.
func ExampleClient_Listen() {
	client := vtunnel.NewClient("ws://sandbox:3001/")
	if err := client.Connect(); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Sandbox port 9000 reaches this machine's localhost:3000.
	if err := client.Listen(9000, "localhost:3000"); err != nil {
		log.Fatal(err)
	}

	// The client can terminate TLS on the way out.
	if err := client.Listen(8085, "tls://www.google.com:443"); err != nil {
		log.Fatal(err)
	}
}

// Generating a CA and extracting the half that may be installed in a sandbox.
func ExampleCACertPEM() {
	blob, err := vtunnel.GenerateCA("vtunnel MITM CA")
	if err != nil {
		log.Fatal(err)
	}
	// Keep the whole blob here: it contains the private key.
	if err := os.WriteFile("ca.pem", blob, 0o600); err != nil {
		log.Fatal(err)
	}

	// Ship only this to the sandbox trust store.
	certOnly, err := vtunnel.CACertPEM(blob)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("ca.crt", certOnly, 0o644); err != nil {
		log.Fatal(err)
	}
}
