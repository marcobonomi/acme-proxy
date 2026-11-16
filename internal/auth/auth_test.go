package auth

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
)

func TestHashToken(t *testing.T) {
	// Known SHA-256 test vector for "abc" (FIPS 180-2).
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	h := HashToken("abc")
	if got := hex.EncodeToString(h[:]); got != want {
		t.Fatalf("HashToken(\"abc\") = %s, want %s", got, want)
	}
}

func TestAuthenticate(t *testing.T) {
	clients := []Client{
		{
			Name:      "app1",
			TokenHash: HashToken("token-app1"),
			Sources:   []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")},
			Domains:   []string{"app1.example.com"},
		},
		{
			Name:      "app2",
			TokenHash: HashToken("token-app2"),
			Sources: []netip.Prefix{
				netip.MustParsePrefix("192.0.2.20/32"),
				netip.MustParsePrefix("198.51.100.0/24"),
			},
			Domains: []string{"app2.example.com"},
		},
	}

	tests := []struct {
		name       string
		user       string
		token      string
		addr       string // empty means an invalid (zero) address
		wantClient string
		wantErr    error
	}{
		// valid
		{"valid", "app1", "token-app1", "192.0.2.10", "app1", nil},
		{"second source network", "app2", "token-app2", "198.51.100.7", "app2", nil},
		{"ipv4-mapped ipv6", "app1", "token-app1", "::ffff:192.0.2.10", "app1", nil},

		// unknown client
		{"unknown client", "app3", "token-app1", "192.0.2.10", "", ErrUnknownClient},
		{"name is case sensitive", "App1", "token-app1", "192.0.2.10", "", ErrUnknownClient},
		{"empty name", "", "token-app1", "192.0.2.10", "", ErrUnknownClient},

		// bad token
		{"wrong token", "app1", "wrong", "192.0.2.10", "", ErrBadToken},
		{"empty token", "app1", "", "192.0.2.10", "", ErrBadToken},
		{"token of another client", "app1", "token-app2", "192.0.2.10", "", ErrBadToken},

		// bad source
		{"wrong address", "app1", "token-app1", "192.0.2.11", "", ErrBadSource},
		{"address of another client", "app1", "token-app1", "192.0.2.20", "", ErrBadSource},
		{"ipv6 address", "app1", "token-app1", "2001:db8::1", "", ErrBadSource},
		{"invalid address", "app1", "token-app1", "", "", ErrBadSource},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var addr netip.Addr
			if tc.addr != "" {
				addr = netip.MustParseAddr(tc.addr)
			}

			got, err := Authenticate(clients, tc.user, tc.token, addr)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil && !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("error %v does not wrap ErrUnauthorized", err)
			}
			if got.Name != tc.wantClient {
				t.Fatalf("client = %q, want %q", got.Name, tc.wantClient)
			}
		})
	}
}
