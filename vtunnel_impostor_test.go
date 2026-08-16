package vtunnel_test

// What a server has to know before the client will talk to it.

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/vivid-money/vtunnel"
)

// The tunnel secret is the only thing that lets a server be the server. Before
// 0.8 the host key was derived from the client's PUBLIC key — a value published
// on purpose, in sandbox images, compose files and CI variables — so anyone who
// read it could compute the server's private host key and the client's pinning
// check verified nothing.
//
// The old attack cannot even be written any more: there is no public value to
// derive from. What remains expressible is the general property, and it is the
// one that matters — a server that does not hold the secret is refused before
// it can do anything.
//
// Anything is precisely the problem. Once a client accepts a server, that
// server drives the tunnel in the direction it was built to go: it opens tunnel
// streams, and the client pipes each one straight into a local address on the
// controlplane — the MITM proxy that injects credentials, or any target passed
// to Client.Listen.
//
// The impostor below speaks the real protocol, so the theft it attempts is the
// one that would actually happen. Only the pinning stops it.
func TestImpostorWithoutTheSecretIsRefused(t *testing.T) {
	// Something only the controlplane can reach.
	private := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("controlplane-only"))
	}))
	defer private.Close()

	// The attacker's server: its own host key, and it accepts whoever turns up,
	// its client auth being entirely under its control.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	stolen := make(chan string, 1)

	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()

		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(hostKey)
		sshConn, chans, reqs, err := ssh.NewServerConn(vtunnel.NewWSConn(ws), cfg)
		if err != nil {
			return // the client saw through it
		}
		defer sshConn.Close()
		go ssh.DiscardRequests(reqs)

		for nc := range chans {
			ch, chReqs, err := nc.Accept()
			if err != nil {
				return
			}
			go ssh.DiscardRequests(chReqs)
			go func() {
				defer ch.Close()
				h, err := readTestFrame(ch)
				if err != nil {
					return
				}
				switch h["type"] {
				case "ping":
					writeTestFrame(ch, map[string]any{"ok": true})
				case "listen":
					port := int(h["port"].(float64))
					writeTestFrame(ch, map[string]any{"ok": true, "port": port})
					go readThroughTunnel(sshConn, port, stolen)
				}
			}()
		}
	}))
	defer impostor.Close()

	client := vtunnel.NewClient(wsURL(impostor), vtunnel.WithSecret(secretA))
	if err := client.Connect(); err != nil {
		return // refused, as it must be
	}
	defer client.Close()

	port := freePort(t)
	if err := client.Listen(port, private.Listener.Addr().String()); err != nil {
		t.Fatal(err)
	}

	select {
	case body := <-stolen:
		t.Fatalf("a server holding no secret reached a controlplane-only service "+
			"through the tunnel and read %q", body)
	case <-time.After(3 * time.Second):
		t.Fatal("the client accepted a host key that proves nothing")
	}
}

// readThroughTunnel does what the real server does — opens a tunnel stream for
// a port the client registered — and speaks HTTP into whatever answers.
func readThroughTunnel(sshConn ssh.Conn, port int, out chan<- string) {
	ch, reqs, err := sshConn.OpenChannel("vtunnel", nil)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	if err := writeTestFrame(ch, map[string]any{"type": "tunnel", "port": port}); err != nil {
		return
	}
	fmt.Fprint(ch, "GET / HTTP/1.1\r\nHost: controlplane\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(ch), nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	select {
	case out <- string(body):
	default:
	}
}

// The wire, spelled out by hand: a 4-byte big-endian length and JSON. Written
// here rather than reused so this test would still describe the protocol if the
// implementation quietly changed it.

func writeTestFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err = w.Write(buf)
	return err
}

func readTestFrame(r io.Reader) (map[string]any, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint32(size[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	var v map[string]any
	return v, json.Unmarshal(b, &v)
}
