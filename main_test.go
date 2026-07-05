package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const sampleJSON = `[
    {"name": "John Smith"},
    {"name": "Jane Doe"},
    {"name": "Zoé Martin"},
    {"name": "  "},
    {"name": "Liam Brown"}
]`

var sampleNames = []string{"John Smith", "Jane Doe", "Zoé Martin", "Liam Brown"}

func TestParseExcludedJSON(t *testing.T) {
	names, err := parseExcludedJSON([]byte(sampleJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(names, sampleNames) {
		t.Fatalf("got %v, want %v", names, sampleNames)
	}
}

func TestParseExcludedJSONInvalid(t *testing.T) {
	if _, err := parseExcludedJSON([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestResolveExcludedSendersInline(t *testing.T) {
	got := resolveExcludedSenders("Alice Martin; Bob Durand ;Carol Petit;;")
	want := []string{"Alice Martin", "Bob Durand", "Carol Petit"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestResolveExcludedSendersEmpty(t *testing.T) {
	if got := resolveExcludedSenders("   "); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestResolveExcludedSendersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "excluded_senders.json")
	if err := os.WriteFile(path, []byte(sampleJSON), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	got := resolveExcludedSenders(path)
	if !reflect.DeepEqual(got, sampleNames) {
		t.Fatalf("got %v, want %v", got, sampleNames)
	}
}

func TestResolveExcludedSendersFileMissingFailsOpen(t *testing.T) {
	// A missing file must not exclude everyone; it returns nil (no extra excludes).
	if got := resolveExcludedSenders("/no/such/path/excluded_senders.json"); got != nil {
		t.Fatalf("expected nil on missing file, got %v", got)
	}
}

func TestResolveExcludedSendersURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleJSON))
	}))
	defer srv.Close()

	got := resolveExcludedSenders(srv.URL + "/api/contacts?simplified=true")
	if !reflect.DeepEqual(got, sampleNames) {
		t.Fatalf("got %v, want %v", got, sampleNames)
	}
}

func TestResolveExcludedSendersURLErrorFailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if got := resolveExcludedSenders(srv.URL); got != nil {
		t.Fatalf("expected nil on HTTP error, got %v", got)
	}
}

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://contacts.example.com/api/contacts?username=user&password=secret": "https://contacts.example.com/api/contacts?<redacted>",
		"https://contacts.example.com/api/contacts":                               "https://contacts.example.com/api/contacts",
	}
	for in, want := range cases {
		if got := redactURL(in); got != want {
			t.Fatalf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchesSenderForwardAllExcept(t *testing.T) {
	excludes := []string{"Alice Martin", "Bob Durand", "Carol Petit"}

	cases := []struct {
		name    string
		sender  string
		matched bool
	}{
		{"unknown sender is forwarded", "Random Person", true},
		{"excluded exact name is dropped", "Bob Durand", false},
		{"excluded is case-insensitive", "alice martin", false},
		{"similar-but-different name is forwarded", "Bob Lefebvre", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesSender("*", excludes, tc.sender); got != tc.matched {
				t.Fatalf("matchesSender(*, %v, %q) = %v, want %v", excludes, tc.sender, got, tc.matched)
			}
		})
	}
}

func TestMatchesSenderInlineDashIsNotExclusion(t *testing.T) {
	// The old "-Name" exclusion syntax inside from_sender has been removed: a
	// "-" token no longer excludes anyone. Exclusions come only from
	// excluded_senders (the excludes argument).
	if !matchesSender("*;-Dave", nil, "Dave") {
		t.Fatal(`inline "-Dave" must no longer exclude Dave; "*" should still match`)
	}
	if matchesSender("*", []string{"Erin"}, "Erin") {
		t.Fatal("excluded_senders entry should drop Erin")
	}
	if !matchesSender("*", []string{"Erin"}, "Someone Else") {
		t.Fatal("non-excluded sender should be forwarded")
	}
}

func TestMatchesSenderWildcardSemantics(t *testing.T) {
	// Only "*" selects all senders. An empty from_sender matches nobody,
	// even against the exclude list.
	if !matchesSender("*", nil, "Anyone") {
		t.Fatal(`"*" must match every sender`)
	}
	if matchesSender("", nil, "Anyone") {
		t.Fatal("empty from_sender must match nobody")
	}
	if matchesSender("", []string{"Someone"}, "Anyone") {
		t.Fatal("empty from_sender must match nobody, regardless of excludes")
	}
	if matchesSender("   ", nil, "Anyone") {
		t.Fatal("whitespace-only from_sender must match nobody")
	}
}

func TestMatchesSenderMultipleIncludes(t *testing.T) {
	// from_sender still supports several ";"-separated include tokens.
	if !matchesSender("Netflix;Bank", nil, "Bank Alert") {
		t.Fatal("Bank Alert should match the Bank include token")
	}
	if matchesSender("Netflix;Bank", nil, "Random Person") {
		t.Fatal("non-matching sender should not match")
	}
}
