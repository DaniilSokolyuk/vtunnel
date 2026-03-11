package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/DaniilSokolyuk/vtunnel"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func main() {
	sizeStr := flag.String("size", "1GB", "data to transfer per connection (e.g. 100MB, 1GB, 10GB)")
	numConns := flag.Int("c", 1, "number of parallel connections")
	mode := flag.String("mode", "all", "benchmark mode: direct, proxy, all")
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

	// Generate key pair for authenticated tunnel
	priv, pub, err := vtunnel.GenerateKeyPair()
	if err != nil {
		fmt.Printf("keygen error: %v\n", err)
		return
	}

	fmt.Printf("vtunnel bench (mode=%s)\n", *mode)
	fmt.Printf("  size: %s x %d conn\n", fmtSize(totalBytes), *numConns)
	fmt.Printf("  auth: ed25519\n\n")

	// Start backend servers
	sinkLn := startSink()
	defer sinkLn.Close()
	sourceLn := startSource()
	defer sourceLn.Close()

	// Start vtunnel server with key auth
	srv := vtunnel.NewServer(vtunnel.WithClientKey(pub))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		srv.HandleConn(conn)
	}))
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")

	// Start vtunnel client with key auth
	client := vtunnel.NewClient(wsURL, vtunnel.WithKeepAlive(-1), vtunnel.WithKey(priv))
	if err := client.Connect(); err != nil {
		fmt.Printf("connect error: %v\n", err)
		return
	}
	defer client.Close()

	if *mode == "direct" || *mode == "all" {
		runDirect(srv, client, sinkLn, sourceLn, totalBytes, *numConns)
	}

	if *mode == "proxy" || *mode == "all" {
		runProxy(srv, client, sinkLn, sourceLn, totalBytes, *numConns)
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

	if err := client.Forward("sink.bench", sinkLn.Addr().String()); err != nil {
		fmt.Printf("forward error: %v\n", err)
		return
	}
	if err := client.Forward("source.bench", sourceLn.Addr().String()); err != nil {
		fmt.Printf("forward error: %v\n", err)
		return
	}
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
	start := time.Now()

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
	printResult(&transferred, start, numConns, len(streams))
}

// benchParallel runs upload and download simultaneously on each connection pair.
func benchParallel(name string, perConn int64, numConns int, upPort, downPort int) {
	total := perConn * int64(numConns) * 2
	fmt.Printf("--- %s ---\n", name)

	var transferred atomic.Int64
	start := time.Now()

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
	printResult(&transferred, start, numConns, 2)
}

func benchProxy(name string, perConn int64, numConns int, proxyAddr string, streams []proxyStream) {
	total := perConn * int64(numConns) * int64(len(streams))
	fmt.Printf("--- %s ---\n", name)

	var transferred atomic.Int64
	start := time.Now()

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
	printResult(&transferred, start, numConns, len(streams))
}

func benchProxyParallel(name string, perConn int64, numConns int, proxyAddr, upHost, downHost string) {
	total := perConn * int64(numConns) * 2
	fmt.Printf("--- %s ---\n", name)

	var transferred atomic.Int64
	start := time.Now()

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
	printResult(&transferred, start, numConns, 2)
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

func printResult(transferred *atomic.Int64, start time.Time, numConns, numStreams int) {
	elapsed := time.Since(start)
	tot := transferred.Load()
	speed := float64(tot) / elapsed.Seconds()

	fmt.Printf("\r  %s in %v\n", fmtSize(tot), elapsed.Round(time.Millisecond))
	fmt.Printf("  throughput: %s/s", fmtSize(int64(speed)))
	if numConns > 1 || numStreams > 1 {
		perStream := speed / float64(numConns) / float64(numStreams)
		fmt.Printf(" (%s/s per stream)", fmtSize(int64(perStream)))
	}
	fmt.Printf("\n\n")
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
