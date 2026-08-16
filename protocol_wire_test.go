package vtunnel

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// The listen request is the only thing the controlplane tells the sandbox.
// It must carry domain names and nothing else: no targets, no credentials, no
// headers. This guards the property by construction, so re-adding a field to
// streamHeader fails here rather than silently shipping secrets into a
// container.
func TestStreamHeaderCarriesOnlyTypePortAndDomains(t *testing.T) {
	var got []string
	typ := reflect.TypeOf(streamHeader{})
	for i := range typ.NumField() {
		got = append(got, typ.Field(i).Name)
	}
	sort.Strings(got)

	want := []string{"Domains", "Port", "Type"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("streamHeader fields = %v, want exactly %v", got, want)
	}

	// And on the wire, too.
	var buf bytes.Buffer
	if err := writeFrame(&buf, streamHeader{Type: streamListen, Port: 42, Domains: []string{"api.corp:443"}}); err != nil {
		t.Fatal(err)
	}
	payload := buf.Bytes()[4:] // past the length prefix
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for key := range decoded {
		if key != "type" && key != "port" && key != "domains" {
			t.Fatalf("unexpected key %q on the wire: %s", key, payload)
		}
	}
}

// A frame round-trips, and a length nobody could mean is refused rather than
// allocated.
func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	sent := streamHeader{Type: streamTunnel, Port: 9001}
	if err := writeFrame(&buf, sent); err != nil {
		t.Fatal(err)
	}
	var got streamHeader
	if err := readFrame(&buf, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, sent) {
		t.Fatalf("round trip gave %+v, want %+v", got, sent)
	}
}

func TestOversizedFrameIsRefused(t *testing.T) {
	// A length prefix claiming far more than any header could be.
	hostile := []byte{0xff, 0xff, 0xff, 0xff}
	var got streamHeader
	if err := readFrame(bytes.NewReader(hostile), &got); err == nil {
		t.Fatal("a 4 GiB frame length was accepted")
	}
}
