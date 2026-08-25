package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vivid-money/vtunnel"
)

func main() {
	sizeStr := flag.String("size", "1GB", "data to transfer per connection (e.g. 100MB, 1GB, 10GB)")
	numConns := flag.Int("c", 1, "number of parallel connections")
	mode := flag.String("mode", "all", "benchmark modes, comma separated: direct, proxy, stream, handshake, all")
	protocol := flag.String("protocol", "all", "session protocol: ssh, yamux, yamux-insecure, all")
	transport := flag.String("transport", "ws", "transport under the session: ws or tcp")
	latency := flag.Duration("latency", 0, "round trip added to the transport, e.g. 50ms (0 = loopback)")
	window := flag.Int("window", 0, "per-stream receive window in bytes (0 = the yamux default; ssh ignores it)")
	iters := flag.Int("n", 2000, "iterations for the stream and handshake modes")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
	memprofile := flag.String("memprofile", "", "write memory profile to file")
	flag.Parse()

	totalBytes, err := parseSize(*sizeStr)
	if err != nil {
		fmt.Fprintf(flag.CommandLine.Output(), "invalid size %q: %v\n", *sizeStr, err)
		flag.Usage()
		return
	}

	// CPU profile
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Printf("cpuprofile: %v\n", err)
			return
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// Silence vtunnel library logs
	log.SetOutput(io.Discard)

	protocols, err := parseProtocols(*protocol)
	if err != nil {
		fmt.Fprintln(flag.CommandLine.Output(), err)
		flag.Usage()
		return
	}

	if *transport != "ws" && *transport != "tcp" {
		fmt.Fprintf(flag.CommandLine.Output(), "unknown transport %q: expected ws or tcp\n", *transport)
		flag.Usage()
		return
	}

	// Start backend servers. They are shared across protocols so that only the
	// session under test differs between runs.
	sinkLn := startSink()
	defer sinkLn.Close()
	sourceLn := startSource()
	defer sourceLn.Close()

	o := benchOpts{
		mode:       *mode,
		transport:  *transport,
		latency:    *latency,
		window:     *window,
		totalBytes: totalBytes,
		numConns:   *numConns,
		iters:      *iters,
		sink:       sinkLn,
		source:     sourceLn,
	}

	fmt.Printf("vtunnel bench (mode=%s, transport=%s)\n", o.mode, o.transport)
	fmt.Printf("  size: %s x %d conn\n", fmtSize(totalBytes), o.numConns)
	fmt.Printf("  latency: %v round trip\n", o.latency)
	if o.window > 0 {
		fmt.Printf("  window: %s per stream (ssh ignores it)\n", fmtSize(int64(o.window)))
	}

	for _, p := range protocols {
		fmt.Printf("\n########## protocol: %s ##########\n\n", p)
		runProtocol(p, o)
	}

	// Memory profile
	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			fmt.Printf("memprofile: %v\n", err)
			return
		}
		defer f.Close()
		runtime.GC()
		pprof.WriteHeapProfile(f)
	}
}

// secret authenticates both ends of the tunnel. Any string does; this one is a
// literal because a benchmark has nobody to hide it from.
//
// yamux-insecure ignores it, which is the point of measuring against it.
const secret = "bench-tunnel-secret-not-for-anything-else"

func parseProtocols(v string) ([]vtunnel.Protocol, error) {
	all := []vtunnel.Protocol{vtunnel.ProtocolSSH, vtunnel.ProtocolYamux, vtunnel.ProtocolYamuxInsecure}
	if v == "all" {
		return all, nil
	}
	for _, p := range all {
		if vtunnel.Protocol(v) == p {
			return []vtunnel.Protocol{p}, nil
		}
	}
	return nil, fmt.Errorf("unknown protocol %q: expected one of ssh, yamux, yamux-insecure, all", v)
}

// benchOpts is everything chosen on the command line, gathered so that the
// tunnel can be stood up identically for every protocol.
type benchOpts struct {
	mode       string
	transport  string
	latency    time.Duration
	window     int
	totalBytes int64
	numConns   int
	iters      int
	sink       net.Listener
	source     net.Listener
}

// wants reports whether mode was asked for. -mode takes a comma-separated
// list, so "stream,handshake" runs two of them and "all" runs every one.
func (o benchOpts) wants(mode string) bool {
	for _, m := range strings.Split(o.mode, ",") {
		if m := strings.TrimSpace(m); m == mode || m == "all" {
			return true
		}
	}
	return false
}

// tunnel stands up a sandbox and a connected controlplane over the chosen
// transport, and returns them with a function that takes them down.
//
// The transport is where the latency is injected, which is the honest place
// for it: the session sits on a net.Conn and has no idea how far away the peer
// is, exactly as in a real deployment.
func tunnel(p vtunnel.Protocol, o benchOpts) (*vtunnel.Server, *vtunnel.Client, func(), error) {
	srv := vtunnel.NewServer(
		vtunnel.WithServerProtocol(p),
		vtunnel.WithServerSecret(secret),
		vtunnel.WithServerStreamWindow(o.window),
	)

	// Both transports are the same two calls; only the scheme differs.
	ln, err := vtunnel.Listen(o.transport + "://127.0.0.1:0")
	if err != nil {
		return nil, nil, nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.HandleConn(withLatency(conn, o.latency))
		}
	}()

	url := fmt.Sprintf("%s://%s", o.transport, ln.Addr())
	base, err := vtunnel.NewDialer(url, nil)
	if err != nil {
		ln.Close()
		return nil, nil, nil, err
	}

	client := vtunnel.NewClient(url,
		vtunnel.WithProtocol(p),
		vtunnel.WithKeepAlive(-1),
		vtunnel.WithSecret(secret),
		vtunnel.WithStreamWindow(o.window),
		vtunnel.WithDialer(func(ctx context.Context) (net.Conn, error) {
			conn, err := base(ctx)
			if err != nil {
				return nil, err
			}
			return withLatency(conn, o.latency), nil
		}),
	)
	if err := client.Connect(); err != nil {
		ln.Close()
		return nil, nil, nil, err
	}
	return srv, client, func() { client.Close(); ln.Close() }, nil
}

// runProtocol runs the selected benchmarks over one session protocol.
// Everything outside the session is held constant, so a difference between
// runs is the session and nothing else.
func runProtocol(p vtunnel.Protocol, o benchOpts) {
	srv, client, stop, err := tunnel(p, o)
	if err != nil {
		fmt.Printf("connect error: %v\n", err)
		return
	}
	defer stop()

	if o.wants("direct") {
		runDirect(srv, client, o.sink, o.source, o.totalBytes, o.numConns)
	}
	if o.wants("proxy") {
		runProxy(srv, client, o.sink, o.source, o.totalBytes, o.numConns)
	}
	if o.wants("stream") {
		runStreams(client, o.sink, o.iters)
	}
	if o.wants("handshake") {
		runHandshake(p, o)
	}
}

// runStreams prices one tunnelled connection. Every request the sandbox
// proxies opens a stream, so this lands on the latency of ordinary traffic in
// a way throughput never shows.
func runStreams(client *vtunnel.Client, target net.Listener, n int) {
	fmt.Printf("=== stream open ===\n\n")

	port := freePort()
	if err := client.Listen(port, target.Addr().String()); err != nil {
		fmt.Printf("listen error: %v\n", err)
		return
	}
	time.Sleep(100 * time.Millisecond)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("--- open, write, close x%d ---\n", n)

	m := startMeter()
	for range n {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Printf("dial error: %v\n", err)
			return
		}
		conn.Write([]byte{1})
		conn.Close()
	}
	printOps(n, m)
}

// runHandshake prices bringing a tunnel up, which happens once per connect and
// again on every reconnect — repeatedly, for a sandbox on a flapping link.
func runHandshake(p vtunnel.Protocol, o benchOpts) {
	fmt.Printf("=== handshake ===\n\n")

	// Handshakes are expensive, and with latency injected each one costs
	// several round trips — a few hundred says as much as a few thousand.
	n := max(o.iters/20, 20)
	fmt.Printf("--- connect and close x%d ---\n", n)

	m := startMeter()
	for range n {
		_, _, stop, err := tunnel(p, o)
		if err != nil {
			fmt.Printf("connect error: %v\n", err)
			return
		}
		stop()
	}
	printOps(n, m)
}

func runDirect(_ *vtunnel.Server, client *vtunnel.Client, sinkLn, sourceLn net.Listener, totalBytes int64, numConns int) {
	fmt.Printf("=== direct (TCP) ===\n\n")

	upPort := freePort()
	downPort := freePort()
	if err := client.Listen(upPort, sinkLn.Addr().String()); err != nil {
		fmt.Printf("listen error: %v\n", err)
		return
	}
	if err := client.Listen(downPort, sourceLn.Addr().String()); err != nil {
		fmt.Printf("listen error: %v\n", err)
		return
	}
	time.Sleep(100 * time.Millisecond)

	bench("upload", totalBytes, numConns, []stream{{port: upPort, upload: true}})
	bench("download", totalBytes, numConns, []stream{{port: downPort, upload: false}})
	bench("upload+download", totalBytes, numConns, []stream{
		{port: upPort, upload: true},
		{port: downPort, upload: false},
	})
	benchParallel("upload+download parallel", totalBytes, numConns, upPort, downPort)
}

func runProxy(srv *vtunnel.Server, client *vtunnel.Client, sinkLn, sourceLn net.Listener, totalBytes int64, numConns int) {
	fmt.Printf("=== proxy (CONNECT) ===\n\n")

	proxyPort := freePort()
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	if err := srv.StartProxy(proxyAddr); err != nil {
		fmt.Printf("proxy error: %v\n", err)
		return
	}
	defer srv.CloseProxy()

	client.Proxy().ForwardTo("sink.bench", sinkLn.Addr().String())
	client.Proxy().ForwardTo("source.bench", sourceLn.Addr().String())
	time.Sleep(100 * time.Millisecond)

	benchProxy("upload", totalBytes, numConns, proxyAddr,
		[]proxyStream{{host: "sink.bench:443", upload: true}})
	benchProxy("download", totalBytes, numConns, proxyAddr,
		[]proxyStream{{host: "source.bench:443", upload: false}})
	benchProxyParallel("upload+download parallel", totalBytes, numConns, proxyAddr,
		"sink.bench:443", "source.bench:443")
}

type stream struct {
	port   int
	upload bool
}

type proxyStream struct {
	host   string
	upload bool
}

// bench runs streams sequentially: for each connection, execute all streams one after another.
func bench(name string, perConn int64, numConns int, streams []stream) {
	total := perConn * int64(numConns) * int64(len(streams))
	fmt.Printf("--- %s ---\n", name)

	var transferred atomic.Int64
	m := startMeter()

	done := make(chan struct{})
	go progress(&transferred, total, done)

	var wg sync.WaitGroup
	for range numConns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, s := range streams {
				transfer(s.port, perConn, s.upload, &transferred)
			}
		}()
	}

	wg.Wait()
	close(done)
	printResult(&transferred, m, numConns, len(streams))
}

// benchParallel runs upload and download simultaneously on each connection pair.
func benchParallel(name string, perConn int64, numConns int, upPort, downPort int) {
	total := perConn * int64(numConns) * 2
	fmt.Printf("--- %s ---\n", name)

	var transferred atomic.Int64
	m := startMeter()

	done := make(chan struct{})
	go progress(&transferred, total, done)

	var wg sync.WaitGroup
	for range numConns {
		wg.Add(2)
		go func() {
			defer wg.Done()
			transfer(upPort, perConn, true, &transferred)
		}()
		go func() {
			defer wg.Done()
			transfer(downPort, perConn, false, &transferred)
		}()
	}

	wg.Wait()
	close(done)
	printResult(&transferred, m, numConns, 2)
}

func benchProxy(name string, perConn int64, numConns int, proxyAddr string, streams []proxyStream) {
	total := perConn * int64(numConns) * int64(len(streams))
	fmt.Printf("--- %s ---\n", name)

	var transferred atomic.Int64
	m := startMeter()

	done := make(chan struct{})
	go progress(&transferred, total, done)

	var wg sync.WaitGroup
	for range numConns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, s := range streams {
				transferViaProxy(proxyAddr, s.host, perConn, s.upload, &transferred)
			}
		}()
	}

	wg.Wait()
	close(done)
	printResult(&transferred, m, numConns, len(streams))
}

func benchProxyParallel(name string, perConn int64, numConns int, proxyAddr, upHost, downHost string) {
	total := perConn * int64(numConns) * 2
	fmt.Printf("--- %s ---\n", name)

	var transferred atomic.Int64
	m := startMeter()

	done := make(chan struct{})
	go progress(&transferred, total, done)

	var wg sync.WaitGroup
	for range numConns {
		wg.Add(2)
		go func() {
			defer wg.Done()
			transferViaProxy(proxyAddr, upHost, perConn, true, &transferred)
		}()
		go func() {
			defer wg.Done()
			transferViaProxy(proxyAddr, downHost, perConn, false, &transferred)
		}()
	}

	wg.Wait()
	close(done)
	printResult(&transferred, m, numConns, 2)
}

func transfer(port int, size int64, upload bool, counter *atomic.Int64) {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fmt.Printf("dial error: %v\n", err)
		return
	}
	defer conn.Close()
	pipeData(conn, conn, size, upload, counter)
}

func transferViaProxy(proxyAddr, host string, size int64, upload bool, counter *atomic.Int64) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		fmt.Printf("dial proxy error: %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		fmt.Printf("CONNECT error: %v\n", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("CONNECT status: %d\n", resp.StatusCode)
		return
	}

	pipeData(br, conn, size, upload, counter)
}

func pipeData(r io.Reader, w io.Writer, size int64, upload bool, counter *atomic.Int64) {
	buf := make([]byte, 64*1024)
	var done int64

	if upload {
		for done < size {
			n := int64(len(buf))
			if rem := size - done; rem < n {
				n = rem
			}
			nw, err := w.Write(buf[:n])
			if err != nil {
				return
			}
			done += int64(nw)
			counter.Add(int64(nw))
		}
	} else {
		for done < size {
			n, err := r.Read(buf)
			if err != nil {
				return
			}
			done += int64(n)
			counter.Add(int64(n))
		}
	}
}

func progress(transferred *atomic.Int64, total int64, done <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var prev int64
	for {
		select {
		case <-ticker.C:
			cur := transferred.Load()
			delta := cur - prev
			prev = cur
			speed := float64(delta) * 2 // per 500ms -> per second
			pct := float64(cur) / float64(total) * 100
			fmt.Printf("\r  %s / %s  %5.1f%%  %s/s  ",
				fmtSize(cur), fmtSize(total), pct, fmtSize(int64(speed)))
		case <-done:
			return
		}
	}
}

// meter records the clock and the allocator at the start of a run.
//
// Allocation is measured alongside throughput because on a data path it is
// throughput: a copy loop that allocates per packet spends its time in the
// collector, and that shows up as a number here rather than as a profile
// somebody has to remember to take.
type meter struct {
	start   time.Time
	alloc   uint64
	mallocs uint64
}

func startMeter() meter {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return meter{start: time.Now(), alloc: ms.TotalAlloc, mallocs: ms.Mallocs}
}

func printResult(transferred *atomic.Int64, m meter, numConns, numStreams int) {
	elapsed := time.Since(m.start)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	tot := transferred.Load()
	speed := float64(tot) / elapsed.Seconds()

	fmt.Printf("\r  %s in %v\n", fmtSize(tot), elapsed.Round(time.Millisecond))
	fmt.Printf("  throughput: %s/s", fmtSize(int64(speed)))
	if numConns > 1 || numStreams > 1 {
		perStream := speed / float64(numConns) / float64(numStreams)
		fmt.Printf(" (%s/s per stream)", fmtSize(int64(perStream)))
	}
	fmt.Println()

	movedMB := float64(tot) / (1 << 20)
	allocBytes := ms.TotalAlloc - m.alloc
	allocs := ms.Mallocs - m.mallocs
	fmt.Printf("  alloc: %s in %s objects", fmtSize(int64(allocBytes)), fmtCount(allocs))
	if movedMB > 0 {
		fmt.Printf(" (%s and %.0f objects per MB moved)",
			fmtSize(int64(float64(allocBytes)/movedMB)), float64(allocs)/movedMB)
	}
	fmt.Printf("\n\n")
}

// printOps reports a benchmark counted in operations rather than bytes.
func printOps(n int, m meter) {
	elapsed := time.Since(m.start)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	perOp := elapsed / time.Duration(n)
	allocBytes := ms.TotalAlloc - m.alloc
	allocs := ms.Mallocs - m.mallocs

	fmt.Printf("  %d ops in %v\n", n, elapsed.Round(time.Millisecond))
	fmt.Printf("  %v per op (%.0f ops/s)\n", perOp.Round(time.Microsecond), float64(n)/elapsed.Seconds())
	fmt.Printf("  alloc: %s and %d objects per op\n\n",
		fmtSize(int64(allocBytes)/int64(n)), allocs/uint64(n))
}

func fmtCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// startSink starts a TCP server that reads and discards everything.
func startSink() net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln
}

// startSource starts a TCP server that writes zeros until the connection closes.
func startSource() net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		buf := make([]byte, 64*1024)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln
}

func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	suffixes := []struct {
		s string
		m int64
	}{
		{"TB", 1 << 40},
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
		{"B", 1},
	}
	for _, sf := range suffixes {
		if strings.HasSuffix(s, sf.s) {
			numStr := strings.TrimSuffix(s, sf.s)
			var num float64
			if _, err := fmt.Sscanf(numStr, "%f", &num); err != nil {
				return 0, fmt.Errorf("invalid number %q", numStr)
			}
			return int64(num * float64(sf.m)), nil
		}
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n, nil
}

func fmtSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
