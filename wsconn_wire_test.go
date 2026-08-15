package vtunnel

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

// The listen request is the only thing the controlplane tells the sandbox.
// It must carry domain names and nothing else: no targets, no credentials, no
// headers. This guards the property by construction, so re-adding a field to
// listenRequest fails here rather than silently shipping secrets into a
// container.
func TestListenRequestCarriesOnlyPortAndDomains(t *testing.T) {
	var got []string
	typ := reflect.TypeOf(listenRequest{})
	for i := range typ.NumField() {
		got = append(got, typ.Field(i).Name)
	}
	sort.Strings(got)

	want := []string{"Domains", "Port"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listenRequest fields = %v, want exactly %v", got, want)
	}

	// And on the wire, too.
	payload := marshalJSON(listenRequest{Port: 42, Domains: []string{"api.corp:443"}})
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for key := range decoded {
		if key != "port" && key != "domains" {
			t.Fatalf("unexpected key %q on the wire: %s", key, payload)
		}
	}
}
