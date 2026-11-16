package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/marcobonomi/acme-proxy/internal/auth"
)

const okValue = "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"

// fakeDNS records the calls it receives instead of talking to a real provider.
type fakeDNS struct {
	calls []string // e.g. "present app1.example.com <value>"
	err   error    // returned by every call, if set
}

func (f *fakeDNS) Present(_ context.Context, name, value string) error {
	f.calls = append(f.calls, "present "+name+" "+value)
	return f.err
}

func (f *fakeDNS) Cleanup(_ context.Context, name, value string) error {
	f.calls = append(f.calls, "cleanup "+name+" "+value)
	return f.err
}

// newTestServer returns a server with one client (app1) and the fake DNS.
// Logs are written to logs, so tests can inspect them.
func newTestServer(dns *fakeDNS, logs io.Writer) *Server {
	clients := []auth.Client{{
		Name:      "app1",
		TokenHash: auth.HashToken("token-app1"),
		Sources:   []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")},
		Domains:   []string{"app1.example.com"},
	}}
	return &Server{
		Clients: func() []auth.Client { return clients },
		DNS:     dns,
		Log:     slog.New(slog.NewTextHandler(logs, nil)),
	}
}

func TestHandler(t *testing.T) {
	validBody := `{"fqdn":"_acme-challenge.app1.example.com.","value":"` + okValue + `"}`

	tests := []struct {
		name      string
		method    string
		path      string
		remote    string // r.RemoteAddr, "ip:port"
		user      string // empty means no basic auth
		token     string
		body      string
		dnsErr    error
		wantCode  int
		wantCalls []string
	}{
		// success
		{"present", "POST", "/present", "192.0.2.10:40000", "app1", "token-app1", validBody, nil,
			http.StatusOK, []string{"present app1.example.com " + okValue}},
		{"cleanup", "POST", "/cleanup", "192.0.2.10:40000", "app1", "token-app1", validBody, nil,
			http.StatusOK, []string{"cleanup app1.example.com " + okValue}},

		// routing
		{"wrong method", "GET", "/present", "192.0.2.10:40000", "app1", "token-app1", "", nil,
			http.StatusMethodNotAllowed, nil},
		{"unknown path", "POST", "/other", "192.0.2.10:40000", "app1", "token-app1", validBody, nil,
			http.StatusNotFound, nil},

		// authentication
		{"no basic auth", "POST", "/present", "192.0.2.10:40000", "", "", validBody, nil,
			http.StatusUnauthorized, nil},
		{"wrong token", "POST", "/present", "192.0.2.10:40000", "app1", "wrong", validBody, nil,
			http.StatusUnauthorized, nil},
		{"wrong source", "POST", "/present", "192.0.2.99:40000", "app1", "token-app1", validBody, nil,
			http.StatusUnauthorized, nil},
		{"unparsable remote address", "POST", "/present", "bogus", "app1", "token-app1", validBody, nil,
			http.StatusUnauthorized, nil},

		// body
		{"malformed json", "POST", "/present", "192.0.2.10:40000", "app1", "token-app1", `{"fqdn":`, nil,
			http.StatusBadRequest, nil},
		{"unknown field", "POST", "/present", "192.0.2.10:40000", "app1", "token-app1",
			`{"fqdn":"_acme-challenge.app1.example.com","value":"` + okValue + `","extra":1}`, nil,
			http.StatusBadRequest, nil},
		{"trailing data", "POST", "/present", "192.0.2.10:40000", "app1", "token-app1", validBody + `{}`, nil,
			http.StatusBadRequest, nil},
		{"body too large", "POST", "/present", "192.0.2.10:40000", "app1", "token-app1",
			`{"fqdn":"` + strings.Repeat("a", 2000) + `"}`, nil,
			http.StatusBadRequest, nil},

		// validation
		{"name not allowed", "POST", "/present", "192.0.2.10:40000", "app1", "token-app1",
			`{"fqdn":"_acme-challenge.other.example.com","value":"` + okValue + `"}`, nil,
			http.StatusForbidden, nil},
		{"invalid value", "POST", "/present", "192.0.2.10:40000", "app1", "token-app1",
			`{"fqdn":"_acme-challenge.app1.example.com","value":"short"}`, nil,
			http.StatusBadRequest, nil},

		// dns provider failure
		{"dns error", "POST", "/present", "192.0.2.10:40000", "app1", "token-app1", validBody,
			errors.New("cloudflare: boom"),
			http.StatusBadGateway, []string{"present app1.example.com " + okValue}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dns := &fakeDNS{err: tc.dnsErr}
			var logs bytes.Buffer
			h := newTestServer(dns, &logs).Handler()

			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.RemoteAddr = tc.remote
			if tc.user != "" {
				req.SetBasicAuth(tc.user, tc.token)
			}
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (logs: %s)", rec.Code, tc.wantCode, logs.String())
			}
			if strings.Join(dns.calls, "\n") != strings.Join(tc.wantCalls, "\n") {
				t.Fatalf("dns calls = %q, want %q", dns.calls, tc.wantCalls)
			}
		})
	}
}

// TestUnauthorizedDoesNotLeakReason checks that the exact reason of an
// authentication failure is logged, but never sent to the client.
func TestUnauthorizedDoesNotLeakReason(t *testing.T) {
	dns := &fakeDNS{}
	var logs bytes.Buffer
	h := newTestServer(dns, &logs).Handler()

	req := httptest.NewRequest("POST", "/present", strings.NewReader("{}"))
	req.RemoteAddr = "192.0.2.10:40000"
	req.SetBasicAuth("app1", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatalf("missing WWW-Authenticate header")
	}
	if strings.Contains(rec.Body.String(), "bad token") {
		t.Fatalf("response body leaks the reason: %q", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "bad token") {
		t.Fatalf("logs do not contain the reason: %s", logs.String())
	}
}

// TestLogInjection checks that a newline in a client-controlled value cannot
// create a fake log line.
func TestLogInjection(t *testing.T) {
	dns := &fakeDNS{}
	var logs bytes.Buffer
	h := newTestServer(dns, &logs).Handler()

	body := `{"fqdn":"_acme-challenge.x\nlevel=INFO msg=done","value":"` + okValue + `"}`
	req := httptest.NewRequest("POST", "/present", strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:40000"
	req.SetBasicAuth("app1", "token-app1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.HasPrefix(line, "level=INFO msg=done") {
			t.Fatalf("injected log line found: %q", line)
		}
	}
}

func TestNewHTTPServerTimeouts(t *testing.T) {
	s := NewHTTPServer(":0", http.NotFoundHandler())
	if s == nil {
		t.Fatal("NewHTTPServer returned nil")
	}
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 {
		t.Fatalf("all timeouts must be set: %+v", s)
	}
	if s.WriteTimeout <= dnsTimeout {
		t.Fatalf("WriteTimeout (%s) must be longer than dnsTimeout (%s)", s.WriteTimeout, dnsTimeout)
	}
}
