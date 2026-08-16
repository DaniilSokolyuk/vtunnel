package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
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
  vtunnel ca [flags]            # MITM CA: makes the pair, exports the certificate

Server flags:
  -listen string       Where to accept the tunnel. The scheme picks the
                       transport, and the client's -server URL must use the
                       same one:
                         ws://:3001/    also serves /health  (default)
                         tcp://:3001    a raw socket, and cheaper
                       Neither is more secure — the session authenticates the
                       peer either way. [$VTUNNEL_LISTEN]
  -proxy string        Where the routing proxy listens (empty = disabled).
                       It serves HTTP and SOCKS5 on the one port, so the
                       sandbox can point HTTP_PROXY and ALL_PROXY at it:
                         9090                      loopback only  (do this)
                         127.0.0.1:9090            the same, spelled out
                         :9090                     every interface — see below
                         mixed://127.0.0.1:9090    both, spelled out
                         socks5://127.0.0.1:1080   one protocol only
                         http://127.0.0.1:8080
                       A scheme needs the whole host:port — the bare-port form
                       and its loopback default do not carry over, so
                       socks5://1080 is an error and socks5://:1080 is every
                       interface. Point SOCKS5 clients at socks5h:// so the
                       name arrives unresolved; an address is refused unless
                       it is forwarded by address too.
                       It authenticates nobody, so a port reachable from
                       outside the sandbox hands whoever finds it an open
                       relay and the controlplane's injected credentials.
                       [$VTUNNEL_PROXY]
  -secret string       Shared tunnel secret, the same value the client is
                       given. Any hard-to-guess string; @/path reads it from
                       a file. [$VTUNNEL_SECRET]
  -protocol string     Session protocol, the same value the client is given:
                       ssh (default), yamux, or yamux-insecure — the last of
                       which has no encryption and no authentication, and is
                       there to be measured against. [$VTUNNEL_PROTOCOL]

CA flags:
  -mitm-ca string   PEM file with CA cert+key, created if missing. Same file
                    the client takes. [$VTUNNEL_MITM_CA] (default ./ca.pem)
  -out string       Where to write the certificate to install in the sandbox
                    (default: the -mitm-ca path with a .crt extension)
  -stdout           Print the certificate to stdout instead of writing a file

Client flags:
  -server string    Tunnel URL. The scheme picks the transport:
                      ws://sandbox:3001/   wss://sandbox.example.com/
                      tcp://sandbox:3001
                    It must match how the sandbox is listening.
  -secret string    Shared tunnel secret, the same value the sandbox is given.
                    Any hard-to-guess string, e.g. openssl rand -base64 32;
                    @/path reads it from a file. [$VTUNNEL_SECRET]
  -protocol string  Session protocol, the same value the sandbox is given:
                    ssh (default), yamux, or yamux-insecure — the last of
                    which has no encryption and no authentication, and is
                    there to be measured against. [$VTUNNEL_PROTOCOL]
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
	case "ca":
		runCA(os.Args[2:])
	default:
		usage()
	}
}

var srv *vtunnel.Server

// readSecret resolves a secret given on the command line. "@/path" reads the
// file instead, because an argument is visible in ps output and lands in shell
// history — and this one value is the whole tunnel.
func readSecret(v string) string {
	path, ok := strings.CutPrefix(v, "@")
	if !ok {
		return v
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[vtunnel] read secret from %s: %v", path, err)
	}
	return strings.TrimSpace(string(b))
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
	listen := fs.String("listen", envOr("VTUNNEL_LISTEN", "ws://:3001/"), "Tunnel listen URL: ws://:3001/ or tcp://:3001")
	proxyAddr := fs.String("proxy", os.Getenv("VTUNNEL_PROXY"),
		"Routing proxy address: 9090 (loopback), 127.0.0.1:9090, :9090 for every interface, "+
			"or mixed|http|socks5://host:port for one front end (empty = disabled)")
	secret := fs.String("secret", os.Getenv("VTUNNEL_SECRET"), "Shared tunnel secret, or @/path to a file")
	protocol := fs.String("protocol", os.Getenv("VTUNNEL_PROTOCOL"), "Session protocol: ssh (default), yamux, or yamux-insecure; must match the client")
	fs.Parse(args)

	listenURL, err := url.Parse(*listen)
	if err != nil || listenURL.Scheme == "" {
		log.Fatalf("[vtunnel] bad -listen %q: want ws://:3001/ or tcp://:3001", *listen)
	}

	opts := []vtunnel.ServerOption{vtunnel.WithServerProtocol(parseProtocol(*protocol))}
	if *secret != "" {
		opts = append(opts, vtunnel.WithServerSecret(readSecret(*secret)))
		log.Println("[vtunnel] Tunnel authentication enabled")
	}
	srv = vtunnel.NewServer(opts...)

	addr, public, err := proxyListenAddr(*proxyAddr)
	if err != nil {
		log.Fatalf("[vtunnel] bad -proxy %q: %v", *proxyAddr, err)
	}
	if addr != "" {
		if err := srv.StartProxy(addr); err != nil {
			log.Fatalf("[vtunnel] Failed to start proxy: %v", err)
		}
		log.Printf("[vtunnel] Routing proxy on %s (no TLS interception here)", addr)
		if public {
			log.Printf("[vtunnel] WARNING: the routing proxy on %s is reachable from outside "+
				"this sandbox. It authenticates nobody: whoever reaches it gets an open relay, "+
				"and for every forwarded domain the controlplane's injected credentials with it. "+
				"Use -proxy 9090 to keep it on loopback unless something else guards the port.",
				addr)
		}
	}

	log.Printf("[vtunnel] Starting server on %s", *listen)

	if listenURL.Scheme != "ws" {
		// Nothing to share the port with, so the transport's own listener is
		// the whole server. /health has no place on a raw socket.
		ln, err := vtunnel.Listen(*listen)
		if err != nil {
			log.Fatalf("[vtunnel] %v", err)
		}
		log.Fatal(vtunnel.Serve(ln, srv))
	}

	// WebSocket shares a mux with the health endpoint, so the HTTP server is
	// ours rather than the transport's.
	http.HandleFunc("/", handleWebSocket)
	http.HandleFunc("/health", handleHealth)

	// ReadHeaderTimeout so a peer that opens a connection and dawdles over the
	// request line cannot pin a goroutine indefinitely. No write or read
	// timeout: once upgraded, this connection is a long-lived tunnel.
	httpSrv := &http.Server{
		Addr:              listenURL.Host,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(httpSrv.ListenAndServe())
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	server := fs.String("server", "", "WebSocket server URL")
	key := fs.String("secret", os.Getenv("VTUNNEL_SECRET"), "Shared tunnel secret, or @/path to a file")
	mitmCAFile := fs.String("mitm-ca", os.Getenv("VTUNNEL_MITM_CA"), "PEM file with CA cert+key for HTTPS MITM (created if missing); unset = no interception")
	protocol := fs.String("protocol", os.Getenv("VTUNNEL_PROTOCOL"), "Session protocol: ssh (default), yamux, or yamux-insecure; must match the sandbox")
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

	opts := []vtunnel.Option{vtunnel.WithProtocol(parseProtocol(*protocol))}
	if *key != "" {
		opts = append(opts, vtunnel.WithSecret(readSecret(*key)))
		log.Println("[vtunnel] Tunnel authentication enabled")
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

// envOr returns the environment variable, or def when it is unset or empty.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// parseProtocol resolves -protocol / $VTUNNEL_PROTOCOL.
//
// An unrecognised value is fatal rather than a fallback to the default. The
// two ends must agree, and a typo that quietly leaves one of them on ssh would
// present as a handshake that never completes.
func parseProtocol(v string) vtunnel.Protocol {
	switch vtunnel.Protocol(v) {
	case "":
		return vtunnel.ProtocolSSH
	case vtunnel.ProtocolSSH:
		return vtunnel.ProtocolSSH
	case vtunnel.ProtocolYamux:
		return vtunnel.ProtocolYamux
	case vtunnel.ProtocolYamuxInsecure:
		return vtunnel.ProtocolYamuxInsecure
	default:
		log.Fatalf("[vtunnel] unknown -protocol %q: expected %q, %q or %q",
			v, vtunnel.ProtocolSSH, vtunnel.ProtocolYamux, vtunnel.ProtocolYamuxInsecure)
		return ""
	}
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
	srv.HandleWebSocket(conn)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}

// proxyListenAddr resolves the -proxy flag into an address to listen on, and
// reports whether that address faces anything beyond the sandbox. An empty
// value means the routing proxy is off.
//
// A bare port is loopback, which is both the common case and the safe one: the
// router has no authentication, so the port is worth exactly as much as the
// credentials the controlplane injects behind it. Anything wider has to be
// written out in full.
func proxyListenAddr(v string) (addr string, public bool, err error) {
	if v == "" {
		return "", false, nil
	}

	// A scheme says which protocols the port serves and belongs to the router;
	// everything below only decides whether the address is reachable from
	// outside the sandbox, which is the part worth warning about.
	scheme, rest, hasScheme := strings.Cut(v, "://")
	if hasScheme {
		switch scheme {
		case "mixed", "http", "socks5":
		default:
			return "", false, fmt.Errorf("unsupported scheme %q (want mixed, http or socks5)", scheme)
		}
		if _, _, splitErr := net.SplitHostPort(rest); splitErr != nil {
			return "", false, fmt.Errorf("%q needs a port, as in %s://127.0.0.1:9090", v, scheme)
		}
	}

	bare := v
	if hasScheme {
		bare = rest
	}

	host, port := "", bare
	if h, p, splitErr := net.SplitHostPort(bare); splitErr == nil {
		host, port = h, p
	} else if strings.ContainsAny(bare, ":.") {
		// Looked like an address and was not one; a bare port contains neither.
		return "", false, fmt.Errorf("want a port (9090) or an address (127.0.0.1:9090)")
	}

	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", false, fmt.Errorf("%q is not a port in 1..65535", port)
	}

	if host == "" && bare == port {
		// A bare port: keep it where only this sandbox can reach it.
		return net.JoinHostPort("127.0.0.1", port), false, nil
	}
	if host == "localhost" {
		return v, false, nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return v, false, nil
	}
	return v, true, nil
}
