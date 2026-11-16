package validate

import (
	"errors"
	"strings"
	"testing"
)

func TestChallenge(t *testing.T) {
	allowed := []string{"app1.example.com", "app2.example.com"}
	const okValue = "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM" // 43 valid characters

	tests := []struct {
		name     string
		fqdn     string
		value    string
		wantName string
		wantErr  error
	}{
		// valid
		{"exact name", "_acme-challenge.app1.example.com", okValue, "app1.example.com", nil},
		{"trailing dot", "_acme-challenge.app1.example.com.", okValue, "app1.example.com", nil},
		{"uppercase", "_ACME-CHALLENGE.App1.Example.COM", okValue, "app1.example.com", nil},
		{"second allowed name", "_acme-challenge.app2.example.com", okValue, "app2.example.com", nil},

		// name not allowed
		{"not in list", "_acme-challenge.other.example.com", okValue, "", ErrNotAllowed},
		{"subdomain of allowed", "_acme-challenge.x.app1.example.com", okValue, "", ErrNotAllowed},
		{"allowed as prefix", "_acme-challenge.app1.example.com.evil.com", okValue, "", ErrNotAllowed},
		{"missing prefix", "app1.example.com", okValue, "", ErrNotAllowed},
		{"only prefix", "_acme-challenge.", okValue, "", ErrNotAllowed},
		{"double prefix", "_acme-challenge._acme-challenge.app1.example.com", okValue, "", ErrNotAllowed},
		{"similar prefix", "_acme-challengex.app1.example.com", okValue, "", ErrNotAllowed},
		{"empty fqdn", "", okValue, "", ErrNotAllowed},
		{"newline in fqdn", "_acme-challenge.app1.example.com\n", okValue, "", ErrNotAllowed},

		// invalid value
		{"value too short", "_acme-challenge.app1.example.com", okValue[:42], "", ErrInvalidValue},
		{"value too long", "_acme-challenge.app1.example.com", okValue + "A", "", ErrInvalidValue},
		{"value empty", "_acme-challenge.app1.example.com", "", "", ErrInvalidValue},
		{"value with padding", "_acme-challenge.app1.example.com", okValue[:42] + "=", "", ErrInvalidValue},
		{"value standard base64", "_acme-challenge.app1.example.com", okValue[:42] + "+", "", ErrInvalidValue},
		{"value with space", "_acme-challenge.app1.example.com", okValue[:42] + " ", "", ErrInvalidValue},
		{"value non ascii", "_acme-challenge.app1.example.com", okValue[:42] + "é", "", ErrInvalidValue},

		// order of checks: the name is checked before the value
		{"bad name and bad value", "_acme-challenge.other.example.com", "x", "", ErrNotAllowed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Challenge(tc.fqdn, tc.value, allowed)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.wantName {
				t.Fatalf("name = %q, want %q", got, tc.wantName)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	label63 := strings.Repeat("a", 63)

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		// valid
		{"simple", "app1.example.com", "app1.example.com", nil},
		{"uppercase and trailing dot", "App1.Example.COM.", "app1.example.com", nil},
		{"label 63 chars", label63 + ".com", label63 + ".com", nil},

		// invalid
		{"empty", "", "", ErrInvalidName},
		{"only dot", ".", "", ErrInvalidName},
		{"no dot", "localhost", "", ErrInvalidName},
		{"double dot inside", "a..b.com", "", ErrInvalidName},
		{"two trailing dots", "a.com..", "", ErrInvalidName},
		{"leading hyphen", "-a.example.com", "", ErrInvalidName},
		{"trailing hyphen", "a-.example.com", "", ErrInvalidName},
		{"underscore", "a_b.example.com", "", ErrInvalidName},
		{"space", "a b.example.com", "", ErrInvalidName},
		{"newline", "a.example.com\n", "", ErrInvalidName},
		{"asterisk", "*.example.com", "", ErrInvalidName},
		{"kelvin sign", "Kube.example.com", "", ErrInvalidName},
		{"label 64 chars", strings.Repeat("a", 64) + ".com", "", ErrInvalidName},
		{"name too long", strings.Join([]string{label63, label63, label63, label63}, "."), "", ErrInvalidName},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeName(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
