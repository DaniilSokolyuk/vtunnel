package main

import (
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

	vtunnel "github.com/DaniilSokolyuk/vtunnel"
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
  -client-key string   Client public key for auth (vt-pub-...) [$VTUNNEL_CLIENT_KEY]

Client flags:
  -server string    WebSocket server URL (e.g. ws://example.com/)
  -key string       Private key for auth (vt-priv-...) [$VTUNNEL_KEY]
  -forward value    Port forward: remotePort=localAddr (repeatable)
                    Examples:
                      -forward 8080=localhost:3000
                      -forward 8085=tls://www.google.com:443
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
	clientKey := fs.String("client-key", os.Getenv("VTUNNEL_CLIENT_KEY"), "Client public key (vt-pub-...)")
	fs.Parse(args)

	var opts []vtunnel.ServerOption
	if *clientKey != "" {
		opts = append(opts, vtunnel.WithClientKey(*clientKey))
		log.Println("[vtunnel] Client key authentication enabled")
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
	fs.Parse(args)

	if *server == "" {
		log.Fatal("[vtunnel] -server is required")
	}
	if len(forwards) == 0 {
		log.Fatal("[vtunnel] at least one -forward is required")
	}

	var opts []vtunnel.Option
	opts = append(opts, vtunnel.WithAutoReconnect(true))
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
		if err := client.Listen(f.remotePort, f.localAddr); err != nil {
			log.Fatalf("[vtunnel] Listen error for port %d: %v", f.remotePort, err)
		}
	}

	// Wait for interrupt
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("[vtunnel] Shutting down")
}

// forward represents a single port forward mapping
type forward struct {
	remotePort int
	localAddr  string
}

// forwardList implements flag.Value for repeatable -forward flags
type forwardList []forward

func (f *forwardList) String() string { return fmt.Sprintf("%v", *f) }

func (f *forwardList) Set(val string) error {
	parts := strings.SplitN(val, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid forward format %q, expected remotePort=localAddr", val)
	}
	port, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid port %q: %v", parts[0], err)
	}
	*f = append(*f, forward{remotePort: port, localAddr: parts[1]})
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
