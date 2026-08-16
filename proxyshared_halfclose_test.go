package vtunnel

// Half-close through the wrappers a connection picks up on its way in.
//
// dualStream asks the connection it is given whether it can half-close, and an
// embedded net.Conn answers for the interface rather than for the thing behind
// it. A wrapper that does not forward CloseWrite therefore turns every
// half-close into a full close, and the peer loses the rest of the response it
// was still streaming.

import (
	"net"
	"testing"
	"time"
)

func TestConnectionWrappersForwardHalfClose(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	tcpLeft, tcpRight := tcpPair(t)

	for _, tc := range []struct {
		name string
		conn net.Conn
		// whether the thing underneath can really half-close
		capable bool
	}{
		{"notifyConn over TCP", &notifyConn{Conn: tcpLeft, release: func() {}}, true},
		{"notifyConn over a pipe", &notifyConn{Conn: left, release: func() {}}, false},
		{"bufferedConn over TCP", newBufferedConn(tcpRight, nil), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cw, ok := tc.conn.(closeWriter)
			if !ok {
				t.Fatalf("%T does not offer CloseWrite, so dualStream cannot half-close through it", tc.conn)
			}
			err := cw.CloseWrite()
			if tc.capable && err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			if !tc.capable && err == nil {
				t.Fatal("reported success on a connection that cannot half-close; " +
					"the peer will wait for an EOF nobody is going to send")
			}
		})
	}
	_ = tcpRight
}

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	dialed, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	t.Cleanup(func() { dialed.Close(); server.Close() })
	return dialed, server
}
