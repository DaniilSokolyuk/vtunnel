package main

import (
	"net"
	"sync"
	"time"
)

// Loopback has no round trip, and a round trip is the only place a receive
// window shows up: one stream cannot exceed window/RTT however fat the link
// is. Real deployments are a laptop talking to a sandbox somewhere else, where
// 20-50 ms is ordinary, so the delay is put in deliberately.
//
// It goes into the transport rather than into the session, which is where it
// belongs: the session sits on a net.Conn and has no idea how far away the
// peer is.

// withLatency holds every byte read from conn for d before handing it over.
// One at each end makes a link with 2*d of round trip; d of zero is conn
// unchanged.
func withLatency(conn net.Conn, d time.Duration) net.Conn {
	if d <= 0 {
		return conn
	}
	// Half at each end, so the flag names the round trip rather than one leg.
	each := d / 2
	c := &delayConn{
		Conn:     conn,
		incoming: make(chan parcel, 1024),
		closed:   make(chan struct{}),
	}
	go func() {
		defer close(c.incoming)
		buf := make([]byte, 64*1024)
		for {
			n, err := conn.Read(buf)
			now := time.Now()
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				select {
				case c.incoming <- parcel{at: now.Add(each), data: b}:
				case <-c.closed:
					return
				}
			}
			if err != nil {
				select {
				case c.incoming <- parcel{at: now.Add(each), err: err}:
				case <-c.closed:
				}
				return
			}
		}
	}()
	return c
}

type delayConn struct {
	net.Conn
	incoming chan parcel
	pending  []byte
	err      error
	once     sync.Once
	closed   chan struct{}
}

type parcel struct {
	at   time.Time
	data []byte
	err  error
}

func (c *delayConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		msg, ok := <-c.incoming
		if !ok {
			c.err = net.ErrClosed
			return 0, c.err
		}
		if wait := time.Until(msg.at); wait > 0 {
			time.Sleep(wait)
		}
		if msg.err != nil {
			c.err = msg.err
		}
		c.pending = msg.data
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *delayConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
