package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// TestParseClientFlags feeds argv-style inputs through a real flag.FlagSet
// and verifies -H / -header binds to the last preceding -forward — exactly
// the order-dependent CLI semantics users interact with.
func TestParseClientFlags(t *testing.T) {
	cases := []struct {
		name         string
		args         []string
		wantErr      string // substring, "" = success expected
		wantForwards []forward
	}{
		{
			name: "single forward, two headers",
			args: []string{
				"-forward", "api.example.test=localhost:8081",
				"-H", "Authorization: Bearer sk-ant-xxx",
				"-H", "X-Env: preview",
			},
			wantForwards: []forward{
				{
					domain:    "api.example.test",
					localAddr: "localhost:8081",
					headers: []forwardHeader{
						{"Authorization", "Bearer sk-ant-xxx"},
						{"X-Env", "preview"},
					},
				},
			},
		},
		{
			name: "two forwards, each with different headers",
			args: []string{
				"-forward", "a.test=localhost:8081",
				"-H", "X-Who: alpha",
				"-forward", "b.test=localhost:8082",
				"-H", "X-Who: bravo",
				"-H", "X-Extra: second",
			},
			wantForwards: []forward{
				{
					domain:    "a.test",
					localAddr: "localhost:8081",
					headers:   []forwardHeader{{"X-Who", "alpha"}},
				},
				{
					domain:    "b.test",
					localAddr: "localhost:8082",
					headers: []forwardHeader{
						{"X-Who", "bravo"},
						{"X-Extra", "second"},
					},
				},
			},
		},
		{
			name: "header alias works identically",
			args: []string{
				"-forward", "api.test=localhost:8081",
				"-header", "Authorization: Bearer xxx",
			},
			wantForwards: []forward{
				{
					domain:    "api.test",
					localAddr: "localhost:8081",
					headers:   []forwardHeader{{"Authorization", "Bearer xxx"}},
				},
			},
		},
		{
			name: "headerless forwards unaffected by surrounding -H",
			args: []string{
				"-forward", "a.test=localhost:8081",
				"-H", "X-Who: alpha",
				"-forward", "b.test=localhost:8082",
				"-forward", "c.test=localhost:8083",
				"-H", "X-Who: charlie",
			},
			wantForwards: []forward{
				{
					domain:    "a.test",
					localAddr: "localhost:8081",
					headers:   []forwardHeader{{"X-Who", "alpha"}},
				},
				{domain: "b.test", localAddr: "localhost:8082"},
				{
					domain:    "c.test",
					localAddr: "localhost:8083",
					headers:   []forwardHeader{{"X-Who", "charlie"}},
				},
			},
		},

		// --- error paths ---
		{
			name: "-H before any -forward",
			args: []string{
				"-H", "Authorization: Bearer xxx",
				"-forward", "api.test=localhost:8081",
			},
			wantErr: "no preceding -forward",
		},
		{
			name: "-H attached to port-flavored forward",
			args: []string{
				"-forward", "8080=localhost:3000",
				"-H", "Authorization: Bearer xxx",
			},
			wantErr: "applies only to domain",
		},
		{
			name: "-H value missing colon",
			args: []string{
				"-forward", "api.test=localhost:8081",
				"-H", "not-a-header",
			},
			wantErr: "Name: Value",
		},
		{
			name: "-H value with empty name",
			args: []string{
				"-forward", "api.test=localhost:8081",
				"-H", ": just-value",
			},
			wantErr: "empty header name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("client", flag.ContinueOnError)
			fs.SetOutput(io.Discard) // suppress flag's own error printing

			var forwards forwardList
			fs.Var(&forwards, "forward", "")
			headers := headerList{forwards: &forwards}
			fs.Var(&headers, "H", "")
			fs.Var(&headers, "header", "")

			err := fs.Parse(tc.args)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil (forwards=%+v)", tc.wantErr, forwards)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			if len(forwards) != len(tc.wantForwards) {
				t.Fatalf("got %d forwards, want %d (got=%+v)", len(forwards), len(tc.wantForwards), forwards)
			}
			for i, want := range tc.wantForwards {
				got := forwards[i]
				if got.domain != want.domain || got.localAddr != want.localAddr || got.remotePort != want.remotePort {
					t.Fatalf("forward[%d]: got %+v, want %+v", i, got, want)
				}
				if len(got.headers) != len(want.headers) {
					t.Fatalf("forward[%d] headers: got %v, want %v", i, got.headers, want.headers)
				}
				for j, wh := range want.headers {
					if got.headers[j] != wh {
						t.Fatalf("forward[%d].headers[%d]: got %+v, want %+v", i, j, got.headers[j], wh)
					}
				}
			}
		})
	}
}
