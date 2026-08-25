package e2e_test

// gRPC through the intercepting proxy, in every call shape gRPC has.
//
// The shape that broke — and the reason this file exists — is the one with no
// body at all. gRPC carries its status in HTTP/2 trailers, except when the
// server has nothing to say but the status: then the whole reply is a single
// HEADERS frame carrying grpc-status with END_STREAM set, and no DATA frame
// ever follows. That is a "trailers-only" reply, and it is what any server
// (Envoy in front of ours, among them) answers for an unknown method — which is
// the very first thing grpcurl asks, since it probes for reflection.
//
// A proxy that flushes the head before copying an empty body turns that one
// frame into two: HEADERS without END_STREAM, then an empty DATA frame that
// ends the stream. Every byte the client needed is still there, and every gRPC
// client still fails — it read the header block as initial metadata and then
// saw a stream finish with no trailers at all: "server closed the stream
// without sending trailers".
//
// So the assertions here are about statuses arriving, not bytes: a call that
// answers Unimplemented must arrive as Unimplemented.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/reflection"
	rpb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"

	"github.com/vivid-money/vtunnel"
)

const (
	echoService = "vtunnel.test.Echo"
	echoUnary   = "/" + echoService + "/Unary"
	echoServer  = "/" + echoService + "/ServerStream"
	echoClient  = "/" + echoService + "/ClientStream"
	echoBidi    = "/" + echoService + "/Bidi"
	echoFails   = "/" + echoService + "/FailsMidStream"
	echoMissing = "/" + echoService + "/NoSuchMethod"
)

// ---------------------------------------------------------------------------
// A service without generated code: raw bytes in, raw bytes out.
//
// Registered under its own content-subtype so the reflection service on the
// same server keeps using the ordinary proto codec — reflection is one of the
// callers being tested, and it speaks real protobuf.
// ---------------------------------------------------------------------------

type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) { return v.(*rawMsg).b, nil }

func (rawCodec) Unmarshal(data []byte, v any) error {
	v.(*rawMsg).b = append([]byte(nil), data...)
	return nil
}

func (rawCodec) Name() string { return "vtunnelraw" }

type rawMsg struct{ b []byte }

func init() { encoding.RegisterCodec(rawCodec{}) }

var echoDesc = grpc.ServiceDesc{
	ServiceName: echoService,
	// Any implementation will do: the handlers below close over nothing and the
	// registration check only asks that the value satisfy this interface.
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "Unary",
		Handler: func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			var in rawMsg
			if err := dec(&in); err != nil {
				return nil, err
			}
			return &rawMsg{b: append([]byte("echo:"), in.b...)}, nil
		},
	}},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ServerStream",
			ServerStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				var in rawMsg
				if err := stream.RecvMsg(&in); err != nil {
					return err
				}
				for i := range 3 {
					if err := stream.SendMsg(&rawMsg{b: fmt.Appendf(nil, "%s#%d", in.b, i)}); err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			StreamName:    "ClientStream",
			ClientStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				var all []byte
				for {
					var in rawMsg
					err := stream.RecvMsg(&in)
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						return err
					}
					all = append(all, in.b...)
				}
				return stream.SendMsg(&rawMsg{b: all})
			},
		},
		{
			StreamName:    "Bidi",
			ClientStreams: true,
			ServerStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				for {
					var in rawMsg
					err := stream.RecvMsg(&in)
					if errors.Is(err, io.EOF) {
						return nil
					}
					if err != nil {
						return err
					}
					if err := stream.SendMsg(&rawMsg{b: append([]byte("pong:"), in.b...)}); err != nil {
						return err
					}
				}
			},
		},
		{
			// The other half of the status story: a status that arrives after a
			// body, in real trailers. This one survived the bug, which is what
			// made it look like gRPC worked.
			StreamName:    "FailsMidStream",
			ServerStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				var in rawMsg
				if err := stream.RecvMsg(&in); err != nil {
					return err
				}
				if err := stream.SendMsg(&rawMsg{b: []byte("first")}); err != nil {
					return err
				}
				return status.Error(codes.ResourceExhausted, "no more for you")
			},
		},
	},
}

// ---------------------------------------------------------------------------
// Harness: a real gRPC server over TLS, reached through the sandbox's egress
// proxy and the tunnel, intercepted by the controlplane's MITM proxy — the
// production path, over loopback.
// ---------------------------------------------------------------------------

func dialGRPCThroughTunnel(t *testing.T) *grpc.ClientConn {
	t.Helper()

	serverCert, serverPool := testServerCert(t)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
	})))
	srv.RegisterService(&echoDesc, struct{}{})
	reflection.Register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	target := lis.Addr().String()

	// Sandbox side: the egress proxy the agent points HTTP_PROXY at.
	ca := generateTestCA(t)
	sandbox := vtunnel.NewServer()
	t.Cleanup(func() { sandbox.Close() })
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	if err := sandbox.StartProxy(proxyAddr); err != nil {
		t.Fatalf("StartProxy: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		sandbox.HandleWebSocket(conn)
	}))
	t.Cleanup(ts.Close)

	// Controlplane side: the MITM proxy that terminates TLS and re-issues the
	// request to the real server.
	client := vtunnel.NewClient(wsURL(ts), vtunnel.WithMitm(ca))
	t.Cleanup(func() { client.Close() })
	client.Proxy().SetTransportTLSConfig(&tls.Config{RootCAs: serverPool})
	if err := client.Proxy().ForwardTo(target, "tls://"+target); err != nil {
		t.Fatalf("ForwardTo: %v", err)
	}
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// The agent's own client: CONNECT through the egress proxy, then TLS to
	// whatever the proxy presents — which is the MITM CA's work, so that is what
	// it trusts.
	caPool := x509.NewCertPool()
	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	caPool.AddCert(caLeaf)

	cc, err := grpc.NewClient(target,
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return connectThroughProxy(ctx, proxyAddr, addr)
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: caPool})),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	waitForRoute(t, cc)
	return cc
}

// waitForRoute waits for the route list to reach the sandbox: it crosses the
// tunnel after the client connects, so the first call can beat it there.
func waitForRoute(t *testing.T, cc *grpc.ClientConn) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := cc.Invoke(ctx, echoUnary, &rawMsg{b: []byte("ping")}, &rawMsg{}, grpc.ForceCodec(rawCodec{}))
		cancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the route never became reachable: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func testServerCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "vtunnel test upstream"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func rawCall() grpc.CallOption { return grpc.ForceCodec(rawCodec{}) }

// ---------------------------------------------------------------------------
// The regression: a reply that is nothing but a status.
// ---------------------------------------------------------------------------

// An unknown method is answered with a trailers-only reply — one HEADERS frame,
// END_STREAM, grpc-status inside. Flattening it into headers plus an empty DATA
// frame leaves the client with "server closed the stream without sending
// trailers" instead of Unimplemented, which is exactly what grpcurl hits on its
// very first reflection probe.
func TestGRPCTrailersOnlyStatusArrives(t *testing.T) {
	cc := dialGRPCThroughTunnel(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := cc.Invoke(ctx, echoMissing, &rawMsg{b: []byte("x")}, &rawMsg{}, rawCall())
	if got := status.Code(err); got != codes.Unimplemented {
		t.Fatalf("code = %v (err %v), want Unimplemented — the status-only reply did not survive the proxy", got, err)
	}
}

// The same shape reached through a stream rather than a unary call: the status
// is the whole reply, and the client learns it on the first Recv.
func TestGRPCTrailersOnlyOnAStream(t *testing.T) {
	cc := dialGRPCThroughTunnel(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, echoMissing, rawCall())
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	if err := stream.SendMsg(&rawMsg{b: []byte("x")}); err != nil {
		t.Logf("SendMsg: %v", err) // the server may already have refused
	}
	_ = stream.CloseSend()
	err = stream.RecvMsg(&rawMsg{})
	if got := status.Code(err); got != codes.Unimplemented {
		t.Fatalf("code = %v (err %v), want Unimplemented", got, err)
	}
}

// ---------------------------------------------------------------------------
// Every call shape, so a fix to one framing case cannot quietly cost another.
// ---------------------------------------------------------------------------

func TestGRPCUnary(t *testing.T) {
	cc := dialGRPCThroughTunnel(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var out rawMsg
	if err := cc.Invoke(ctx, echoUnary, &rawMsg{b: []byte("hello")}, &out, rawCall()); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if string(out.b) != "echo:hello" {
		t.Fatalf("reply = %q, want %q", out.b, "echo:hello")
	}
}

func TestGRPCServerStreaming(t *testing.T) {
	cc := dialGRPCThroughTunnel(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, echoServer, rawCall())
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	if err := stream.SendMsg(&rawMsg{b: []byte("m")}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}

	var got []string
	for {
		var out rawMsg
		err := stream.RecvMsg(&out)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("RecvMsg: %v", err)
		}
		got = append(got, string(out.b))
	}
	if want := "m#0,m#1,m#2"; strings.Join(got, ",") != want {
		t.Fatalf("messages = %v, want %s", got, want)
	}
}

func TestGRPCClientStreaming(t *testing.T) {
	cc := dialGRPCThroughTunnel(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true}, echoClient, rawCall())
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	for _, part := range []string{"a", "b", "c"} {
		if err := stream.SendMsg(&rawMsg{b: []byte(part)}); err != nil {
			t.Fatalf("SendMsg %q: %v", part, err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}

	var out rawMsg
	if err := stream.RecvMsg(&out); err != nil {
		t.Fatalf("RecvMsg: %v", err)
	}
	if string(out.b) != "abc" {
		t.Fatalf("reply = %q, want %q", out.b, "abc")
	}
	// The status still has to arrive after it.
	if err := stream.RecvMsg(&rawMsg{}); !errors.Is(err, io.EOF) {
		t.Fatalf("second RecvMsg = %v, want EOF (an OK status)", err)
	}
}

func TestGRPCBidiStreaming(t *testing.T) {
	cc := dialGRPCThroughTunnel(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, echoBidi, rawCall())
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}

	// Interleaved, so the reply really does come back while the request is still
	// open — the shape reflection uses, and the one a proxy that buffers either
	// direction turns into a deadlock.
	for _, msg := range []string{"one", "two"} {
		if err := stream.SendMsg(&rawMsg{b: []byte(msg)}); err != nil {
			t.Fatalf("SendMsg %q: %v", msg, err)
		}
		var out rawMsg
		if err := stream.RecvMsg(&out); err != nil {
			t.Fatalf("RecvMsg after %q: %v", msg, err)
		}
		if want := "pong:" + msg; string(out.b) != want {
			t.Fatalf("reply = %q, want %q", out.b, want)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	if err := stream.RecvMsg(&rawMsg{}); !errors.Is(err, io.EOF) {
		t.Fatalf("final RecvMsg = %v, want EOF (an OK status)", err)
	}
}

// A status that follows a body travels in real trailers. This is the case that
// kept working while trailers-only was broken, which is what made the bug look
// like "gRPC works, only reflection is broken".
func TestGRPCStatusAfterMessages(t *testing.T) {
	cc := dialGRPCThroughTunnel(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, echoFails, rawCall())
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	if err := stream.SendMsg(&rawMsg{b: []byte("go")}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	_ = stream.CloseSend()

	var first rawMsg
	if err := stream.RecvMsg(&first); err != nil {
		t.Fatalf("first RecvMsg: %v", err)
	}
	if string(first.b) != "first" {
		t.Fatalf("first message = %q", first.b)
	}
	err = stream.RecvMsg(&rawMsg{})
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("code = %v (err %v), want ResourceExhausted", got, err)
	}
}

// ---------------------------------------------------------------------------
// Reflection, because it is what every gRPC tool does first.
// ---------------------------------------------------------------------------

func TestGRPCServerReflection(t *testing.T) {
	cc := dialGRPCThroughTunnel(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stream, err := rpb.NewServerReflectionClient(cc).ServerReflectionInfo(ctx)
	if err != nil {
		t.Fatalf("ServerReflectionInfo: %v", err)
	}
	if err := stream.Send(&rpb.ServerReflectionRequest{
		MessageRequest: &rpb.ServerReflectionRequest_ListServices{ListServices: "*"},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	var names []string
	for _, svc := range resp.GetListServicesResponse().GetService() {
		names = append(names, svc.GetName())
	}
	if !slices.Contains(names, echoService) {
		t.Fatalf("services = %v, want one of them to be %s", names, echoService)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
}
