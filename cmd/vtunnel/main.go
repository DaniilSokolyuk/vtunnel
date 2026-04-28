package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/gorilla/websocket"

	vtunnel "github.com/vivid-money/vtunnel"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  vtunnel server [flags]
  vtunnel client [flags]
  vtunnel keygen

Server flags:
  -port int            WebSocket listen port (default 3001)
  -proxy int           HTTP CONNECT proxy port (0 = disabled, default 0)
  -proxy-mitm-ca string PEM file with CA cert+key for HTTPS MITM (enables interception)
  -client-key string   Client public key for auth (vt-pub-...) [$VTUNNEL_CLIENT_KEY]

Client flags:
  -server string    WebSocket server URL (e.g. ws://example.com/)
  -key string       Private key for auth (vt-priv-...) [$VTUNNEL_KEY]
  -forward value    Forward mapping (repeatable)
                    Port:   -forward 8080=localhost:3000
                    Domain: -forward llmproxy.local=localhost:8080
                    TLS:    -forward 8085=tls://www.google.com:443
  -H value          Inject HTTP header into MITM-proxied requests for the
  -header value     preceding -forward (domain-flavored). Format "Name: Value".
                    Repeatable. Each -H attaches to the most recent -forward.
`)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "keygen":
		runKeygen()
	default:
		usage()
	}
}

var srv *vtunnel.Server

func runKeygen() {
	priv, pub, err := vtunnel.GenerateKeyPair()
	if err != nil {
		log.Fatalf("[vtunnel] keygen error: %v", err)
	}
	fmt.Printf("Private key (client): %s\n", priv)
	fmt.Printf("Public key (server):  %s\n", pub)
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	port := fs.Int("port", 3001, "WebSocket listen port")
	proxyPort := fs.Int("proxy", 0, "HTTP CONNECT proxy port (0 = disabled)")
	mitmCAFile := fs.String("proxy-mitm-ca", "", "PEM file with CA cert+key for HTTPS MITM")
	clientKey := fs.String("client-key", os.Getenv("VTUNNEL_CLIENT_KEY"), "Client public key (vt-pub-...)")
	fs.Parse(args)

	var opts []vtunnel.ServerOption
	if *clientKey != "" {
		opts = append(opts, vtunnel.WithClientKey(*clientKey))
		log.Println("[vtunnel] Client key authentication enabled")
	}
	if *mitmCAFile != "" {
		pem, err := os.ReadFile(*mitmCAFile)
		if err != nil {
			log.Fatalf("[vtunnel] Failed to read MITM CA file: %v", err)
		}
		cert, err := tls.X509KeyPair(pem, pem)
		if err != nil {
			log.Fatalf("[vtunnel] Failed to parse MITM CA cert+key: %v", err)
		}
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Fatalf("[vtunnel] Failed to parse MITM CA leaf: %v", err)
		}
		opts = append(opts, vtunnel.WithProxyMitmCA(cert))
		log.Println("[vtunnel] HTTPS MITM interception enabled")
	}
	srv = vtunnel.NewServer(opts...)

	if *proxyPort > 0 {
		proxyAddr := fmt.Sprintf(":%d", *proxyPort)
		if err := srv.StartProxy(proxyAddr); err != nil {
			log.Fatalf("[vtunnel] Failed to start proxy: %v", err)
		}
		log.Printf("[vtunnel] CONNECT proxy on %s", proxyAddr)
	}

	http.HandleFunc("/", handleWebSocket)
	http.HandleFunc("/health", handleHealth)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("[vtunnel] Starting server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	server := fs.String("server", "", "WebSocket server URL")
	key := fs.String("key", os.Getenv("VTUNNEL_KEY"), "Private key (vt-priv-...)")
	var forwards forwardList
	fs.Var(&forwards, "forward", "Port forward: remotePort=localAddr (repeatable)")
	headers := headerList{forwards: &forwards}
	fs.Var(&headers, "H", "Header injected into MITM-proxied requests for the preceding domain -forward")
	fs.Var(&headers, "header", "Alias for -H")
	fs.Parse(args)

	if *server == "" {
		log.Fatal("[vtunnel] -server is required")
	}
	if len(forwards) == 0 {
		log.Fatal("[vtunnel] at least one -forward is required")
	}

	var opts []vtunnel.Option
	if *key != "" {
		opts = append(opts, vtunnel.WithKey(*key))
		log.Println("[vtunnel] Key authentication enabled")
	}
	client := vtunnel.NewClient(*server, opts...)
	if err := client.Connect(); err != nil {
		log.Fatalf("[vtunnel] Connect error: %v", err)
	}
	defer client.Close()

	for _, f := range forwards {
		if f.domain != "" {
			var opts []vtunnel.ForwardOption
			for _, h := range f.headers {
				opts = append(opts, vtunnel.WithHeader(h.name, h.value))
			}
			if err := client.Forward(f.domain, f.localAddr, opts...); err != nil {
				log.Fatalf("[vtunnel] Forward error for %s: %v", f.domain, err)
			}
		} else {
			if err := client.Listen(f.remotePort, f.localAddr); err != nil {
				log.Fatalf("[vtunnel] Listen error for port %d: %v", f.remotePort, err)
			}
		}
	}

	// Wait for interrupt
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("[vtunnel] Shutting down")
}

// forward represents a single forward mapping (port-based or domain-based)
type forward struct {
	remotePort int    // port-based forward (mutually exclusive with domain)
	domain     string // domain-based forward (mutually exclusive with remotePort)
	localAddr  string
	headers    []forwardHeader
}

type forwardHeader struct {
	name  string
	value string
}

// forwardList implements flag.Value for repeatable -forward flags
type forwardList []forward

func (f *forwardList) String() string { return fmt.Sprintf("%v", *f) }

func (f *forwardList) Set(val string) error {
	parts := strings.SplitN(val, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid forward format %q, expected port=localAddr or domain=localAddr", val)
	}
	left, right := parts[0], parts[1]
	if port, err := strconv.Atoi(left); err == nil {
		*f = append(*f, forward{remotePort: port, localAddr: right})
	} else {
		*f = append(*f, forward{domain: left, localAddr: right})
	}
	return nil
}

// headerList implements flag.Value for repeatable -H/-header flags.
// Each value attaches to the most recently appended entry in the referenced
// forwardList, which mirrors how the flags appear on the CLI (Go stdlib flag
// calls Set in argument order).
type headerList struct {
	forwards *forwardList
}

func (h *headerList) String() string { return "" }

func (h *headerList) Set(val string) error {
	if h.forwards == nil || len(*h.forwards) == 0 {
		return fmt.Errorf("-H/-header %q: no preceding -forward", val)
	}
	last := &(*h.forwards)[len(*h.forwards)-1]
	if last.domain == "" {
		return fmt.Errorf("-H/-header %q: applies only to domain -forward (got port %d)", val, last.remotePort)
	}
	name, value, ok := strings.Cut(val, ":")
	if !ok {
		return fmt.Errorf("-H/-header %q: expected \"Name: Value\"", val)
	}
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" {
		return fmt.Errorf("-H/-header %q: empty header name", val)
	}
	last.headers = append(last.headers, forwardHeader{name: name, value: value})
	return nil
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[vtunnel] Upgrade error: %v", err)
		return
	}
	defer conn.Close()
	srv.HandleConn(conn)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
