package normalize

import (
	"encoding/json"
	"testing"
)

func TestFromPredicateCycloneDX(t *testing.T) {
	raw := json.RawMessage(`{
		"components": [
			{"name": "openssl", "version": "3.1.4", "licenses": [{"license": {"id": "Apache-2.0"}}]},
			{"name": "musl", "version": "1.2.4", "licenses": [{"license": {"name": "MIT License"}}]},
			{"name": "no-license", "version": "0.1.0"}
		]
	}`)

	got, err := FromPredicate("https://cyclonedx.org/bom", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []Component{
		{Name: "openssl", Version: "3.1.4", License: "Apache-2.0"},
		{Name: "musl", Version: "1.2.4", License: "MIT License"},
		{Name: "no-license", Version: "0.1.0", License: ""},
	}
	assertComponentsEqual(t, got, want)
}

func TestFromPredicateSPDX(t *testing.T) {
	raw := json.RawMessage(`{
		"packages": [
			{"name": "openssl", "versionInfo": "3.1.4", "licenseConcluded": "Apache-2.0"},
			{"name": "musl", "versionInfo": "1.2.4", "licenseConcluded": "NOASSERTION", "licenseDeclared": "MIT"},
			{"name": "no-license", "versionInfo": "0.1.0", "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION"}
		]
	}`)

	got, err := FromPredicate("https://spdx.dev/Document", raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []Component{
		{Name: "openssl", Version: "3.1.4", License: "Apache-2.0"},
		{Name: "musl", Version: "1.2.4", License: "MIT"},
		{Name: "no-license", Version: "0.1.0", License: ""},
	}
	assertComponentsEqual(t, got, want)
}

func TestFromPredicateUnsupported(t *testing.T) {
	if _, err := FromPredicate("https://example.com/unknown", json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected error for unsupported predicate type, got none")
	}
}

func assertComponentsEqual(t *testing.T, got, want []Component) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d components, want %d (%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("component %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
