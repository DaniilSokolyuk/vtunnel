package vtunnel_test

import (
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

	// A private service, reached with a credential the sandbox never receives.
	if err := client.Forward("api.corp", "localhost:8081",
		vtunnel.WithHeader("Authorization", "Bearer "+os.Getenv("API_TOKEN")),
	); err != nil {
		log.Fatal(err)
	}

	// Passthrough: a :443 target is dialed over TLS, with the protocol the
	// upstream really supports mirrored back to the application.
	if err := client.Forward("gitlab.corp", "gitlab.corp:443"); err != nil {
		log.Fatal(err)
	}

	// Every subdomain to one service.
	if err := client.Forward("*.preview.corp", "localhost:8082"); err != nil {
		log.Fatal(err)
	}

	select {} // serve until killed
}

// Forwards can be changed while connected. Each call re-sends the full domain
// list; the sandbox router replaces its allowlist with it.
func ExampleClient_Unforward() {
	client := vtunnel.NewClient("ws://sandbox:3001/")
	if err := client.Connect(); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	if err := client.Forward("api.corp", "localhost:8081"); err != nil {
		log.Fatal(err)
	}

	// Later: stop serving it. api.corp now egresses from the sandbox directly.
	if err := client.Unforward("api.corp"); err != nil {
		log.Fatal(err)
	}
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
