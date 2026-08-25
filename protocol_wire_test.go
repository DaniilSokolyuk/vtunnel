package vtunnel

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// What the controlplane tells the sandbox is domain names and the sandbox's own
// egress rules — no targets, no credentials, no headers. This guards the
// property by construction, so adding a field to streamHeader fails here rather
// than silently shipping secrets into a container.
//
// A policy passes that test and a target would not, which is worth stating
// plainly because the two look similar from a distance. A rule says what this
// sandbox may reach, which the sandbox is the one enforcing and could observe
// anyway by trying; a target says where a name really goes on the
// controlplane's network, which is knowledge the sandbox has no way to obtain
// and no business holding.
func TestStreamHeaderCarriesOnlyTypePortDomainsAndPolicy(t *testing.T) {
	var got []string
	typ := reflect.TypeOf(streamHeader{})
	for i := range typ.NumField() {
		got = append(got, typ.Field(i).Name)
	}
	sort.Strings(got)

	want := []string{"Domains", "Policy", "Port", "Type"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("streamHeader fields = %v, want exactly %v", got, want)
	}

	// The policy is rules and a default, and carries nothing else.
	var policyFields []string
	policyType := reflect.TypeOf(wirePolicy{})
	for i := range policyType.NumField() {
		policyFields = append(policyFields, policyType.Field(i).Name)
	}
	sort.Strings(policyFields)
	if wantPolicy := []string{"Allow", "Default", "Deny"}; !reflect.DeepEqual(policyFields, wantPolicy) {
		t.Fatalf("wirePolicy fields = %v, want exactly %v", policyFields, wantPolicy)
	}

	// And on the wire, too. A listen request carries no policy key at all: the
	// two are separate messages, so that a policy needs no port to be allocated
	// for it and a large one cannot overflow the frame a forward travels in.
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

// The default crosses as a word. ActionAllow is the zero value, so a number
// would make an absent field, a truncated frame and "allow everything" the same
// message — and that mistake fails open.
func TestWirePolicyDefaultIsAWordAndUnknownWordsAreRefused(t *testing.T) {
	var buf bytes.Buffer
	sent := streamHeader{Type: streamPolicy, Policy: newWirePolicy(Policy{
		Default: ActionDeny,
		Allow:   []string{"*.example.com"},
	})}
	if err := writeFrame(&buf, sent); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"default":"deny"`)) {
		t.Fatalf("the default did not travel as a word: %s", buf.Bytes()[4:])
	}

	var got streamHeader
	if err := readFrame(&buf, &got); err != nil {
		t.Fatal(err)
	}
	p, err := got.Policy.policy()
	if err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if p.Default != ActionDeny || !reflect.DeepEqual(p.Allow, []string{"*.example.com"}) {
		t.Fatalf("round trip gave %+v", p)
	}

	// A default nobody wrote, and one nobody recognises, are both refused rather
	// than read as allow.
	for _, bad := range []string{"", "permit", "DENY "} {
		if _, err := (&wirePolicy{Default: bad}).policy(); err == nil {
			t.Errorf("default %q was accepted", bad)
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
