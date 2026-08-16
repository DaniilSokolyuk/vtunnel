package main

// Where the sandbox's routing proxy listens.
//
// It used to be `-proxy 9090` and a hardcoded `:9090` — every interface — with
// no way to say otherwise. The router authenticates nobody: it relays to any
// host it is asked for, and for an allowlisted domain it returns what the
// controlplane fetched with the credentials it injected. Anything that can
// reach the port therefore gets an open relay and the controlplane's
// credentials at once: a neighbouring container on the same bridge, a pod on
// the same node, an SSRF in another service.
//
// So the flag takes an address, a bare port still means the loopback one, and
// anything wider is a deliberate act that gets said out loud in the log.

import "testing"

func TestProxyListenAddr(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantAddr   string
		wantPublic bool
		wantErr    bool
	}{
		{name: "disabled", in: "", wantAddr: ""},
		{name: "bare port is loopback", in: "9090", wantAddr: "127.0.0.1:9090"},
		{name: "explicit loopback", in: "127.0.0.1:9090", wantAddr: "127.0.0.1:9090"},
		{name: "localhost by name", in: "localhost:9090", wantAddr: "localhost:9090"},
		{name: "IPv6 loopback", in: "[::1]:9090", wantAddr: "[::1]:9090"},
		{name: "every interface, the short way", in: ":9090", wantAddr: ":9090", wantPublic: true},
		{name: "every interface, spelled out", in: "0.0.0.0:9090", wantAddr: "0.0.0.0:9090", wantPublic: true},
		{name: "a routable address", in: "10.0.0.7:9090", wantAddr: "10.0.0.7:9090", wantPublic: true},
		{name: "not a port", in: "nine thousand", wantErr: true},
		{name: "no port at all", in: "10.0.0.7", wantErr: true},
		{name: "port out of range", in: "70000", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, public, err := proxyListenAddr(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("proxyListenAddr(%q) = %q, want an error", tc.in, addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("proxyListenAddr(%q): %v", tc.in, err)
			}
			if addr != tc.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tc.wantAddr)
			}
			if public != tc.wantPublic {
				t.Errorf("public = %v, want %v: this decides whether the operator is warned "+
					"that the sandbox's credentials-bearing proxy is reachable from outside it",
					public, tc.wantPublic)
			}
		})
	}
}
