package vtunnel

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// dialTimeout bounds only the dial to the chained proxy. After the CONNECT line
// was written, reading the answer blocked forever, so a controlplane that
// accepts TCP and then goes quiet — mid-reconnect, swapped out, a wedged hop —
// pinned one goroutine and two sockets per request from the sandbox.
func TestEgressChainedConnectHasAReplyDeadline(t *testing.T) {
	prev := connectReplyTimeout
	connectReplyTimeout = 200 * time.Millisecond
	t.Cleanup(func() { connectReplyTimeout = prev })

	// A "controlplane" that accepts and never answers.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()

	egress := newEgressProxy()
	if err := egress.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer egress.Close()
	egress.SetRoutes(silent.Addr().(*net.TCPAddr).Port, []string{"quiet.test"})

	conn, err := net.DialTimeout("tcp", egress.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the egress proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "CONNECT quiet.test:443 HTTP/1.1\r\nHost: quiet.test:443\r\n\r\n")

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("the egress proxy never answered in %v: the chained CONNECT has no read deadline (%v)", elapsed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("the egress proxy reported a tunnel to a proxy that never accepted it")
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("the egress proxy took %v to give up", elapsed)
	}
}
