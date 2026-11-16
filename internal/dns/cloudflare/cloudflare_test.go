package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testZone  = "023e105f4ecef8ad9ca31a8372d0c353"
	testToken = "test-token-do-not-leak"
	testValue = "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"
	testName  = "app1.example.com"
	testFQDN  = "_acme-challenge.app1.example.com"
)

// fakeCloudflare is a minimal, in-memory imitation of the Cloudflare DNS
// records API. It stores records, logs every request, and can be told to
// misbehave.
type fakeCloudflare struct {
	mu       sync.Mutex
	records  []record
	nextID   int
	requests []string // "METHOD path?query"
	lastBody []byte   // body of the last POST
	lastHdr  http.Header

	// ignoreFilters makes GET return every record, as if the API ignored
	// the query string.
	ignoreFilters bool
	// override, if set, replaces the normal handler.
	override http.HandlerFunc
}

func (f *fakeCloudflare) add(typ, name, content string) string {
	f.nextID++
	id := fmt.Sprintf("%032x", f.nextID)
	f.records = append(f.records, record{ID: id, Type: typ, Name: name, Content: content, TTL: 60})
	return id
}

func (f *fakeCloudflare) addWithID(id, typ, name, content string) {
	f.records = append(f.records, record{ID: id, Type: typ, Name: name, Content: content, TTL: 60})
}

func (f *fakeCloudflare) ids() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.records {
		out = append(out, r.ID)
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func cfError(w http.ResponseWriter, status, code int, msg string) {
	writeJSON(w, status, map[string]any{
		"success":  false,
		"errors":   []Message{{Code: code, Message: msg}},
		"messages": []Message{},
		"result":   nil,
	})
}

func cfOK(w http.ResponseWriter, result any) {
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"errors":   []Message{},
		"messages": []Message{},
		"result":   result,
	})
}

func (f *fakeCloudflare) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /zones/{zone}/dns_records", func(w http.ResponseWriter, r *http.Request) {
		var rec record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			cfError(w, http.StatusBadRequest, 9207, "Request body is invalid.")
			return
		}
		b, _ := json.Marshal(rec)
		f.lastBody = b
		for _, e := range f.records {
			if e.Type == rec.Type && strings.EqualFold(e.Name, rec.Name) && e.Content == rec.Content {
				cfError(w, http.StatusBadRequest, 81058, "An identical record already exists.")
				return
			}
		}
		rec.ID = f.add(rec.Type, rec.Name, rec.Content)
		cfOK(w, rec)
	})

	mux.HandleFunc("GET /zones/{zone}/dns_records", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		out := []record{}
		for _, e := range f.records {
			if !f.ignoreFilters {
				if t := q.Get("type"); t != "" && e.Type != t {
					continue
				}
				if n := q.Get("name.exact"); n != "" && !strings.EqualFold(e.Name, n) {
					continue
				}
			}
			out = append(out, e)
		}
		cfOK(w, out)
	})

	mux.HandleFunc("DELETE /zones/{zone}/dns_records/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		for i, e := range f.records {
			if e.ID == id {
				f.records = slices.Delete(f.records, i, i+1)
				cfOK(w, map[string]string{"id": id})
				return
			}
		}
		cfError(w, http.StatusNotFound, 81044, "Record does not exist.")
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()

		req := r.Method + " " + r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			req += "?" + r.URL.RawQuery
		}
		f.requests = append(f.requests, req)
		f.lastHdr = r.Header.Clone()

		if f.override != nil {
			f.override(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			cfError(w, http.StatusForbidden, 10000, "Authentication error")
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/zones/"+testZone+"/") {
			cfError(w, http.StatusNotFound, 7003, "Could not route to /zones/..., perhaps your object identifier is invalid?")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// newTestClient starts a fake Cloudflare and returns a client pointed at it.
func newTestClient(t *testing.T, f *fakeCloudflare) *Client {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)

	c, err := New(testZone, testToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.baseURL = srv.URL
	c.http = srv.Client()
	return c
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		zoneID  string
		token   string
		wantErr error
	}{
		{"valid", testZone, testToken, nil},
		{"empty zone", "", testToken, ErrInvalidZoneID},
		{"zone too short", testZone[:31], testToken, ErrInvalidZoneID},
		{"zone too long", testZone + "0", testToken, ErrInvalidZoneID},
		{"zone uppercase", strings.ToUpper(testZone), testToken, ErrInvalidZoneID},
		{"zone with path", "../../../user/tokens/verify00000000", testToken, ErrInvalidZoneID},
		{"zone with newline", testZone + "\n", testToken, ErrInvalidZoneID},
		{"empty token", testZone, "", ErrEmptyToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(tt.zoneID, tt.token)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("New() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil {
				if c == nil {
					t.Fatal("New() returned nil client")
				}
				if c.baseURL != DefaultBaseURL {
					t.Errorf("baseURL = %q, want %q", c.baseURL, DefaultBaseURL)
				}
				if c.http == nil || c.http.Timeout <= 0 {
					t.Error("http client must have a timeout")
				}
			} else if c != nil {
				t.Error("New() returned a client together with an error")
			}
		})
	}
}

func TestPresent(t *testing.T) {
	f := &fakeCloudflare{}
	c := newTestClient(t, f)

	if err := c.Present(context.Background(), testName, testValue); err != nil {
		t.Fatalf("Present: %v", err)
	}

	if len(f.records) != 1 {
		t.Fatalf("got %d records, want 1", len(f.records))
	}
	got := f.records[0]
	if got.Type != "TXT" {
		t.Errorf("type = %q, want TXT", got.Type)
	}
	if got.Name != testFQDN {
		t.Errorf("name = %q, want %q", got.Name, testFQDN)
	}
	if want := `"` + testValue + `"`; got.Content != want {
		t.Errorf("content = %q, want %q (TXT content must be quoted)", got.Content, want)
	}

	var sent record
	if err := json.Unmarshal(f.lastBody, &sent); err != nil {
		t.Fatalf("decoding sent body: %v", err)
	}
	if sent.TTL != 60 {
		t.Errorf("ttl = %d, want 60", sent.TTL)
	}
	if sent.ID != "" {
		t.Errorf("request must not contain an id, got %q", sent.ID)
	}

	if want := "POST /zones/" + testZone + "/dns_records"; f.requests[0] != want {
		t.Errorf("request = %q, want %q", f.requests[0], want)
	}
	if ct := f.lastHdr.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestPresentIsIdempotent(t *testing.T) {
	f := &fakeCloudflare{}
	c := newTestClient(t, f)

	for i := range 2 {
		if err := c.Present(context.Background(), testName, testValue); err != nil {
			t.Fatalf("Present #%d: %v", i+1, err)
		}
	}
	if len(f.records) != 1 {
		t.Errorf("got %d records, want 1", len(f.records))
	}
}

func TestPresentAPIError(t *testing.T) {
	f := &fakeCloudflare{}
	c := newTestClient(t, f)
	c.token = "wrong-token-also-secret"

	err := c.Present(context.Background(), testName, testValue)
	if err == nil {
		t.Fatal("Present: expected an error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %v (%T) is not an *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if len(apiErr.Errors) != 1 || apiErr.Errors[0].Code != 10000 {
		t.Errorf("Errors = %+v, want one error with code 10000", apiErr.Errors)
	}
	msg := err.Error()
	if !strings.Contains(msg, "10000") || !strings.Contains(msg, "Authentication error") {
		t.Errorf("error message %q should contain the Cloudflare code and message", msg)
	}
	if strings.Contains(msg, "wrong-token-also-secret") {
		t.Errorf("error message %q leaks the token", msg)
	}
}

func TestCleanup(t *testing.T) {
	f := &fakeCloudflare{}
	target := f.add("TXT", testFQDN, `"`+testValue+`"`)
	otherValue := f.add("TXT", testFQDN, `"another-challenge-value-for-a-wildcard-cert"`)
	otherName := f.add("TXT", "_acme-challenge.app2.example.com", `"`+testValue+`"`)
	c := newTestClient(t, f)

	if err := c.Cleanup(context.Background(), testName, testValue); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if got := f.ids(); slices.Contains(got, target) {
		t.Error("target record was not deleted")
	}
	for _, keep := range []string{otherValue, otherName} {
		if !slices.Contains(f.ids(), keep) {
			t.Errorf("record %s was deleted but should have been kept", keep)
		}
	}

	if !slices.ContainsFunc(f.requests, func(r string) bool {
		return strings.HasPrefix(r, "GET /zones/"+testZone+"/dns_records?") &&
			strings.Contains(r, "type=TXT") &&
			strings.Contains(r, "name.exact="+testFQDN)
	}) {
		t.Errorf("no GET filtered by type and exact name; requests: %q", f.requests)
	}
}

func TestCleanupUnquotedRecord(t *testing.T) {
	f := &fakeCloudflare{}
	target := f.add("TXT", testFQDN, testValue)
	c := newTestClient(t, f)

	if err := c.Cleanup(context.Background(), testName, testValue); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if slices.Contains(f.ids(), target) {
		t.Error("unquoted record with the same value was not deleted")
	}
}

func TestCleanupValueIsCaseSensitive(t *testing.T) {
	f := &fakeCloudflare{}
	keep := f.add("TXT", testFQDN, `"`+strings.ToLower(testValue)+`"`)
	c := newTestClient(t, f)

	if err := c.Cleanup(context.Background(), testName, testValue); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if !slices.Contains(f.ids(), keep) {
		t.Error("record whose value differs only in case was deleted")
	}
}

func TestCleanupNothingToDelete(t *testing.T) {
	f := &fakeCloudflare{}
	c := newTestClient(t, f)

	if err := c.Cleanup(context.Background(), testName, testValue); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	for _, r := range f.requests {
		if strings.HasPrefix(r, "DELETE") {
			t.Errorf("unexpected request %q", r)
		}
	}
}

func TestCleanupDoesNotTrustFilters(t *testing.T) {
	f := &fakeCloudflare{ignoreFilters: true}
	target := f.add("TXT", testFQDN, `"`+testValue+`"`)
	keepA := f.add("A", testFQDN, testValue)
	keepName := f.add("TXT", "_acme-challenge.app2.example.com", `"`+testValue+`"`)
	keepSuffix := f.add("TXT", "x"+testFQDN, `"`+testValue+`"`)
	c := newTestClient(t, f)

	if err := c.Cleanup(context.Background(), testName, testValue); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	ids := f.ids()
	if slices.Contains(ids, target) {
		t.Error("target record was not deleted")
	}
	for _, keep := range []string{keepA, keepName, keepSuffix} {
		if !slices.Contains(ids, keep) {
			t.Errorf("record %s was deleted although the API returned it unfiltered", keep)
		}
	}
}

func TestCleanupEscapesRecordID(t *testing.T) {
	f := &fakeCloudflare{}
	f.addWithID("id/with/slashes", "TXT", testFQDN, `"`+testValue+`"`)
	c := newTestClient(t, f)

	if err := c.Cleanup(context.Background(), testName, testValue); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(f.ids()) != 0 {
		t.Error("record was not deleted")
	}
	want := "DELETE /zones/" + testZone + "/dns_records/id%2Fwith%2Fslashes"
	if !slices.Contains(f.requests, want) {
		t.Errorf("missing %q; requests: %q", want, f.requests)
	}
}

func TestCleanupAPIError(t *testing.T) {
	f := &fakeCloudflare{}
	c := newTestClient(t, f)
	c.token = "wrong"

	err := c.Cleanup(context.Background(), testName, testValue)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Cleanup error = %v, want an *APIError", err)
	}
}

func TestInvalidResponse(t *testing.T) {
	tests := []struct {
		name string
		h    http.HandlerFunc
	}{
		{"html error page", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "<html><body>502 Bad Gateway</body></html>")
		}},
		{"empty body", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}},
		{"success false with 200", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"success": false, "errors": []Message{{Code: 1000, Message: "boom"}}})
		}},
		{"error status with success true", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"success": true, "result": nil})
		}},
		{"huge body", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"success":true,"result":"`)
			fmt.Fprint(w, strings.Repeat("a", 2<<20))
			fmt.Fprint(w, `"}`)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeCloudflare{override: tt.h}
			c := newTestClient(t, f)
			if err := c.Present(context.Background(), testName, testValue); err == nil {
				t.Error("Present: expected an error")
			}
			if err := c.Cleanup(context.Background(), testName, testValue); err == nil {
				t.Error("Cleanup: expected an error")
			}
		})
	}
}

func TestContextIsHonoured(t *testing.T) {
	// The fake server never answers: it waits until the client gives up,
	// until the test ends, or 3 seconds as a safety net so that a broken
	// client cannot hang the test suite.
	release := make(chan struct{})
	f := &fakeCloudflare{override: func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		case <-time.After(3 * time.Second):
		}
	}}
	c := newTestClient(t, f)
	t.Cleanup(func() { close(release) }) // runs before the server is closed

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.Present(ctx, testName, testValue)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Present error = %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Present took %v; the context deadline was ignored", d)
	}
}

func TestAuthorizationHeader(t *testing.T) {
	f := &fakeCloudflare{}
	c := newTestClient(t, f)

	if err := c.Present(context.Background(), testName, testValue); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got := f.lastHdr.Get("Authorization"); got != "Bearer "+testToken {
		t.Errorf("Authorization = %q, want Bearer token", got)
	}
	for _, r := range f.requests {
		if strings.Contains(r, testToken) {
			t.Errorf("token found in URL %q", r)
		}
	}
}

func TestAPIError(t *testing.T) {
	tests := []struct {
		name    string
		err     *APIError
		want    string
		has     int
		hasWant bool
	}{
		{"no messages", &APIError{StatusCode: 500}, "cloudflare: HTTP 500", 1000, false},
		{"one message", &APIError{StatusCode: 403, Errors: []Message{{10000, "Authentication error"}}},
			"cloudflare: HTTP 403; 10000: Authentication error", 10000, true},
		{"two messages", &APIError{StatusCode: 400, Errors: []Message{{1004, "DNS Validation Error"}, {81058, "An identical record already exists."}}},
			"cloudflare: HTTP 400; 1004: DNS Validation Error; 81058: An identical record already exists.", 81058, true},
		{"code not present", &APIError{StatusCode: 400, Errors: []Message{{1004, "DNS Validation Error"}}},
			"cloudflare: HTTP 400; 1004: DNS Validation Error", 81058, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
			if got := tt.err.hasCode(tt.has); got != tt.hasWant {
				t.Errorf("hasCode(%d) = %v, want %v", tt.has, got, tt.hasWant)
			}
		})
	}
}
