package session

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// streamType is the only SSH channel type vtunnel opens. There used to be
// several concepts on the wire — channel types, extra data, global requests —
// and they are gone: yamux offers none of them, so anything expressed with
// them could not be expressed once for both backends.
const streamType = "vtunnel"

type sshSession struct {
	conn  ssh.Conn
	chans <-chan ssh.NewChannel
	local net.Addr
	peer  net.Addr
}

func dialSSH(conn net.Conn, cfg Config) (Session, error) {
	sc := &ssh.ClientConfig{User: "vtunnel"}
	if cfg.Keys != nil {
		signer, err := cfg.Keys.ClientSigner()
		if err != nil {
			return nil, fmt.Errorf("client key: %w", err)
		}
		host, err := cfg.Keys.HostSigner()
		if err != nil {
			return nil, fmt.Errorf("host key: %w", err)
		}
		sc.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
		sc.HostKeyCallback = ssh.FixedHostKey(host.PublicKey())
	} else {
		sc.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", sc)
	if err != nil {
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	go ssh.DiscardRequests(reqs)

	return &sshSession{conn: sshConn, chans: chans, local: conn.LocalAddr(), peer: conn.RemoteAddr()}, nil
}

func serveSSH(conn net.Conn, cfg Config) (Session, error) {
	sc := &ssh.ServerConfig{}
	if cfg.Keys != nil {
		host, err := cfg.Keys.HostSigner()
		if err != nil {
			return nil, fmt.Errorf("host key: %w", err)
		}
		sc.AddHostKey(host)

		client, err := cfg.Keys.ClientSigner()
		if err != nil {
			return nil, fmt.Errorf("client key: %w", err)
		}
		expected := client.PublicKey().Marshal()
		sc.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), expected) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unauthorized key")
		}
	} else {
		host, err := ephemeralHostKey()
		if err != nil {
			return nil, err
		}
		sc.AddHostKey(host)
		sc.NoClientAuth = true
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sc)
	if err != nil {
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	go ssh.DiscardRequests(reqs)

	return &sshSession{conn: sshConn, chans: chans, local: conn.LocalAddr(), peer: conn.RemoteAddr()}, nil
}

func (s *sshSession) Open() (net.Conn, error) {
	ch, reqs, err := s.conn.OpenChannel(streamType, nil)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)
	return s.wrap(ch), nil
}

func (s *sshSession) Accept() (net.Conn, error) {
	for nc := range s.chans {
		if nc.ChannelType() != streamType {
			nc.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(reqs)
		return s.wrap(ch), nil
	}
	return nil, io.EOF
}

func (s *sshSession) Wait() error  { return s.conn.Wait() }
func (s *sshSession) Close() error { return s.conn.Close() }

func (s *sshSession) wrap(ch ssh.Channel) net.Conn {
	return &sshStream{Channel: ch, local: s.local, peer: s.peer}
}

// sshStream presents an SSH channel as a net.Conn.
//
// The addresses are the underlying connection's — every stream shares them,
// which is honest: they are multiplexed over the one socket. Deadlines are the
// one thing an SSH channel genuinely cannot do, so they say so instead of
// quietly succeeding and never firing.
type sshStream struct {
	ssh.Channel
	local, peer net.Addr
}

func (s *sshStream) LocalAddr() net.Addr                { return s.local }
func (s *sshStream) RemoteAddr() net.Addr               { return s.peer }
func (s *sshStream) SetDeadline(time.Time) error        { return errors.ErrUnsupported }
func (s *sshStream) SetReadDeadline(time.Time) error    { return errors.ErrUnsupported }
func (s *sshStream) SetWriteDeadline(t time.Time) error { return errors.ErrUnsupported }

// ephemeralHostKey backs the unauthenticated mode, where the host key proves
// nothing and one per process is as good as one per connection.
var ephemeralHostKey = sync.OnceValues(func() (ssh.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	return ssh.NewSignerFromKey(key)
})
