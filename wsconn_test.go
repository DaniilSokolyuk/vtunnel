package vtunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestWriteReadMsgRoundTrip(t *testing.T) {
	type msg struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	var buf bytes.Buffer
	sent := msg{Name: "hello", Value: 42}
	if err := writeMsg(&buf, sent); err != nil {
		t.Fatalf("writeMsg: %v", err)
	}

	var got msg
	if err := readMsg(&buf, &got); err != nil {
		t.Fatalf("readMsg: %v", err)
	}
	if got != sent {
		t.Fatalf("got %+v, want %+v", got, sent)
	}
}

func TestWriteReadMsgMultiple(t *testing.T) {
	var buf bytes.Buffer

	msgs := []controlRequest{
		{ID: 1, Type: "listen", listenRequest: listenRequest{Port: 8080, LocalAddr: "localhost:3000"}},
		{ID: 2, Type: "listen", listenRequest: listenRequest{Port: 0, LocalAddr: "localhost:8080", Domain: "app.test"}},
	}

	for _, m := range msgs {
		if err := writeMsg(&buf, m); err != nil {
			t.Fatalf("writeMsg: %v", err)
		}
	}

	for i, want := range msgs {
		var got controlRequest
		if err := readMsg(&buf, &got); err != nil {
			t.Fatalf("readMsg[%d]: %v", i, err)
		}
		if got.ID != want.ID || got.Type != want.Type || got.Port != want.Port || got.LocalAddr != want.LocalAddr || got.Domain != want.Domain {
			t.Fatalf("msg[%d]: got %+v, want %+v", i, got, want)
		}
	}
}

func TestReadMsgTooLarge(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxMsgSize+1)
	buf.Write(hdr[:])
	buf.Write(make([]byte, 100)) // doesn't matter, should fail on size check

	var v struct{}
	err := readMsg(&buf, &v)
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
}

func TestReadMsgEOF(t *testing.T) {
	var v struct{}
	err := readMsg(bytes.NewReader(nil), &v)
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestReadMsgTruncated(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 100) // claims 100 bytes
	buf.Write(hdr[:])
	buf.Write([]byte("short")) // only 5 bytes

	var v struct{}
	err := readMsg(&buf, &v)
	if err == nil {
		t.Fatal("expected error for truncated message")
	}
}

func TestControlRequestResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer

	req := controlRequest{
		ID:            1,
		Type:          "listen",
		listenRequest: listenRequest{Port: 8080, LocalAddr: "localhost:3000"},
	}
	if err := writeMsg(&buf, req); err != nil {
		t.Fatalf("writeMsg request: %v", err)
	}

	var gotReq controlRequest
	if err := readMsg(&buf, &gotReq); err != nil {
		t.Fatalf("readMsg request: %v", err)
	}
	if gotReq.ID != 1 || gotReq.Type != "listen" || gotReq.Port != 8080 {
		t.Fatalf("unexpected request: %+v", gotReq)
	}

	resp := controlResponse{
		ID:            1,
		OK:            true,
		listenRequest: listenRequest{Port: 8080},
	}
	if err := writeMsg(&buf, resp); err != nil {
		t.Fatalf("writeMsg response: %v", err)
	}

	var gotResp controlResponse
	if err := readMsg(&buf, &gotResp); err != nil {
		t.Fatalf("readMsg response: %v", err)
	}
	if gotResp.ID != 1 || !gotResp.OK || gotResp.Port != 8080 {
		t.Fatalf("unexpected response: %+v", gotResp)
	}
}
