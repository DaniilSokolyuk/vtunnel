package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	vtunnel "github.com/vivid-money/vtunnel"
)

var upgrader = vtunnel.NewUpgrader()

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  vtunnel server [flags]        # runs in the sandbox: routes, never decrypts
  vtunnel client [flags]        # runs on the controlplane: MITM, credentials
  vtunnel keygen                # tunnel authentication keypair
  vtunnel ca [flags]            # MITM CA: makes the pair, exports the certificate

Server flags:
  -port int            WebSocket listen port (default 3001)
  -proxy int           HTTP CONNECT proxy port (0 = disabled, default 0)
  -client-key string   Client public key for auth (vt-pub-...) [$VTUNNEL_CLIENT_KEY]

CA flags:
  -mitm-ca string   PEM file with CA cert+key, created if missing. Same file
                    the client takes. [$VTUNNEL_MITM_CA] (default ./ca.pem)
  -out string       Where to write the certificate to install in the sandbox
                    (default: the -mitm-ca path with a .crt extension)
  -stdout           Print the certificate to stdout instead of writing a file

Client flags:
  -server string    WebSocket server URL (e.g. ws://example.com/)
  -key string       Private key for auth (vt-priv-...) [$VTUNNEL_KEY]
  -mitm-ca string   PEM file with CA cert+key for HTTPS MITM [$VTUNNEL_MITM_CA]
                    Created if missing. Without it TLS is piped through
                    untouched and -H cannot be used.
  -forward value    Forward mapping (repeatable)
                    Port:   -forward 8080=localhost:3000
                    Domain: -forward llmproxy.local=localhost:8080
                    Real host: -forward gitlab.corp
                            No target = route it to itself, TLS untouched.
                            Use for upstreams that pin certificates; nothing
                            is decrypted, so -H does not apply.
                    TLS:    -forward 8085=tls://www.google.com:443
  -H value          Inject HTTP header into requests for the preceding
  -header value     -forward (domain-flavored). Format "Name: Value".
                    Repeatable. Each -H attaches to the most recent -forward.
                    Values never leave this machine.
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
	case "ca":
		runCA(os.Args[2:])
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

// defaultCAName is where the MITM CA lands when no path is given: the working
// directory, so the files are where you ran the command and not hidden in a
// home directory you have to remember.
const defaultCAName = "ca.pem"

// loadOrCreateCA reads the CA at path, generating one if it does not exist yet.
// The file is written 0600: it holds a key that can mint trusted certificates.
func loadOrCreateCA(path string) (tls.Certificate, error) {
	blob, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		blob, err = vtunnel.GenerateCA("vtunnel MITM CA")
		if err != nil {
			return tls.Certificate{}, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return tls.Certificate{}, fmt.Errorf("create CA directory: %w", err)
		}
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			return tls.Certificate{}, fmt.Errorf("write CA: %w", err)
		}
		log.Printf("[vtunnel] Generated a new MITM CA at %s", path)
	} else if err != nil {
		return tls.Certificate{}, fmt.Errorf("read CA: %w", err)
	}
	return vtunnel.LoadCA(blob)
}

// certExportPath decides where the certificate half is written, and refuses to
// name the CA pair itself.
//
// The default swaps the extension for .crt, which is right for the conventional
// ca.pem and catastrophic for a CA already called ca.crt: the export would
// overwrite the pair with a certificate-only file, destroying the private key.
// There is no recovering from that — every sandbox trusting the CA needs a new
// one — so it is refused rather than warned about.
func certExportPath(caPath, out string) (string, error) {
	path := out
	if path == "" {
		path = strings.TrimSuffix(caPath, filepath.Ext(caPath)) + ".crt"
	}

	if filepath.Clean(path) == filepath.Clean(caPath) || sameFile(path, caPath) {
		return "", fmt.Errorf(
			"refusing to write the certificate over the CA at %s: that would destroy its private key; "+
				"pass -out with a different path, or name the pair something other than %s",
			caPath, filepath.Base(caPath))
	}
	return path, nil
}

// sameFile reports whether two paths resolve to the same file on disk, which
// plain string comparison misses across symlinks and hard links.
func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// runCA generates the MITM CA if it does not exist yet and writes its two
// halves as separate files: the cert+key PEM to keep here, and the certificate
// on its own to install in a sandbox. Running it again re-exports the
// certificate from the existing CA rather than making a new one.
func runCA(args []string) {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	caFile := fs.String("mitm-ca", os.Getenv("VTUNNEL_MITM_CA"), "PEM file with CA cert+key (created if missing)")
	out := fs.String("out", "", "Where to write the certificate (default: alongside the CA, as .crt)")
	toStdout := fs.Bool("stdout", false, "Print the certificate to stdout instead of writing a file")
	fs.Parse(args)

	path := *caFile
	if path == "" {
		path = defaultCAName
	}
	if _, err := loadOrCreateCA(path); err != nil {
		log.Fatalf("[vtunnel] MITM CA: %v", err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[vtunnel] read CA: %v", err)
	}
	certPEM, err := vtunnel.CACertPEM(blob)
	if err != nil {
		log.Fatalf("[vtunnel] extract CA certificate: %v", err)
	}

	if *toStdout {
		os.Stdout.Write(certPEM)
		return
	}

	certPath, err := certExportPath(path, *out)
	if err != nil {
		log.Fatalf("[vtunnel] %v", err)
	}
	// 0644: this half is meant to be copied around and read by anything.
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		log.Fatalf("[vtunnel] write certificate: %v", err)
	}

	fmt.Fprintf(os.Stderr, "CA ready.\n")
	fmt.Fprintf(os.Stderr, "  private key + cert  %s   keep here, pass to: vtunnel client -mitm-ca\n", path)
	fmt.Fprintf(os.Stderr, "  certificate only    %s   copy into the sandbox trust store\n", certPath)
	fmt.Fprintf(os.Stderr, "\n%s can mint certificates every sandbox trusts. Do not commit it.\n", path)
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
		log.Printf("[vtunnel] Routing proxy on %s (no TLS interception here)", proxyAddr)
	}

	http.HandleFunc("/", handleWebSocket)
	http.HandleFunc("/health", handleHealth)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("[vtunnel] Starting server on %s", addr)

	// ReadHeaderTimeout so a peer that opens a connection and dawdles over the
	// request line cannot pin a goroutine indefinitely. No write or read
	// timeout: once upgraded, this connection is a long-lived tunnel.
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	server := fs.String("server", "", "WebSocket server URL")
	key := fs.String("key", os.Getenv("VTUNNEL_KEY"), "Private key (vt-priv-...)")
	mitmCAFile := fs.String("mitm-ca", os.Getenv("VTUNNEL_MITM_CA"), "PEM file with CA cert+key for HTTPS MITM (created if missing); unset = no interception")
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

	// No CA, no interception. Headers can only be injected into traffic we
	// terminate, so asking for both at once is a mistake worth naming rather
	// than silently dropping the header.
	if *mitmCAFile == "" {
		if name := forwards.firstHeaderName(); name != "" {
			log.Fatalf("[vtunnel] -H %q needs -mitm-ca: headers can only be injected into intercepted TLS", name)
		}
		log.Println("[vtunnel] No -mitm-ca: TLS is piped through untouched")
	} else {
		cert, err := loadOrCreateCA(*mitmCAFile)
		if err != nil {
			log.Fatalf("[vtunnel] MITM CA: %v", err)
		}
		opts = append(opts, vtunnel.WithMitm(cert))
		log.Printf("[vtunnel] HTTPS MITM enabled, CA %s (private key stays on this machine)", *mitmCAFile)
	}

	client := vtunnel.NewClient(*server, opts...)
	if err := client.Connect(); err != nil {
		log.Fatalf("[vtunnel] Connect error: %v", err)
	}
	defer client.Close()

	for _, f := range forwards {
		if f.domain != "" {
			// Routes live on the proxy; the client mirrors them into the sandbox.
			if f.localAddr == "" {
				// No target: route the domain to itself, TLS untouched.
				client.Proxy().Forward(f.domain)
				continue
			}
			var opts []vtunnel.ForwardOption
			for _, h := range f.headers {
				opts = append(opts, vtunnel.WithHeader(h.name, h.value))
			}
			if err := client.Proxy().ForwardTo(f.domain, f.localAddr, opts...); err != nil {
				log.Fatalf("[vtunnel] %v", err)
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
	localAddr  string // empty for a domain = route it to itself, TLS untouched
	headers    []forwardHeader
}

type forwardHeader struct {
	name  string
	value string
}

// firstHeaderName returns the name of the first configured -H header, or "" if
// none were given.
func (f forwardList) firstHeaderName() string {
	for _, fwd := range f {
		if len(fwd.headers) > 0 {
			return fwd.headers[0].name
		}
	}
	return ""
}

// forwardList implements flag.Value for repeatable -forward flags
type forwardList []forward

func (f *forwardList) String() string { return fmt.Sprintf("%v", *f) }

func (f *forwardList) Set(val string) error {
	left, right, hasTarget := strings.Cut(val, "=")
	if !hasTarget {
		// "-forward gitlab.corp": the domain stands for itself. A port form
		// has nowhere to send its connections, so it still needs a target.
		if _, err := strconv.Atoi(left); err == nil {
			return fmt.Errorf("invalid forward %q: a port forward needs a target, e.g. %s=localhost:3000", val, left)
		}
		if strings.Contains(left, "*") {
			return fmt.Errorf("invalid forward %q: a wildcard has no host to stand for, give it a target", val)
		}
		*f = append(*f, forward{domain: left})
		return nil
	}
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
	if last.localAddr == "" {
		return fmt.Errorf("-H %q: %s has no target, so its TLS is never terminated and there is nothing to inject into; give it one, e.g. -forward %s=%s:443",
			val, last.domain, last.domain, last.domain)
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
