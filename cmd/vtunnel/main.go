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
	"time"

	"github.com/gorilla/websocket"

	vtunnel "github.com/DaniilSokolyuk/vtunnel"
)

const defaultHandshakeTimeout = 60 * time.Second

var upgrader = websocket.Upgrader{
	HandshakeTimeout: defaultHandshakeTimeout,
	CheckOrigin:      func(r *http.Request) bool { return true },
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  vtunnel server [flags]
  vtunnel client [flags]

Server flags:
  -port int    WebSocket listen port (default 3001)

Client flags:
  -server string    WebSocket server URL (e.g. ws://example.com/)
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
	default:
		usage()
	}
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	port := fs.Int("port", 3001, "WebSocket listen port")
	fs.Parse(args)

	http.HandleFunc("/", handleWebSocket)
	http.HandleFunc("/health", handleHealth)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("[vtunnel] Starting server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	server := fs.String("server", "", "WebSocket server URL")
	var forwards forwardList
	fs.Var(&forwards, "forward", "Port forward: remotePort=localAddr (repeatable)")
	fs.Parse(args)

	if *server == "" {
		log.Fatal("[vtunnel] -server is required")
	}
	if len(forwards) == 0 {
		log.Fatal("[vtunnel] at least one -forward is required")
	}

	client := vtunnel.NewClient(*server, vtunnel.WithAutoReconnect(true))
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

	server := vtunnel.NewServer()
	server.HandleConn(conn)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
