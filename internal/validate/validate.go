// Package validate checks DNS names and ACME DNS-01 challenge requests.
package validate

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

var (
	ErrInvalidName  = errors.New("invalid name")
	ErrNotAllowed   = errors.New("name not allowed")
	ErrInvalidValue = errors.New("invalid challenge value")
)

var (
	// nameRE matches a hostname with at least two labels. Each label is 1-63
	// characters long, contains only ASCII letters, digits and hyphens, and
	// does not start or end with a hyphen.
	nameRE = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

	// valueRE matches a DNS-01 TXT value: a SHA-256 digest encoded as
	// base64url without padding, which is always 43 characters long
	// (RFC 8555, section 8.4).
	valueRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// NormalizeName validates a hostname and returns its canonical form
// (lowercase, no trailing dot). It is used when loading the configuration.
//
// The name is validated before being lowercased: strings.ToLower follows
// Unicode rules and can turn non-ASCII characters into ASCII letters
// (e.g. the Kelvin sign U+212A becomes "k").
func NormalizeName(name string) (string, error) {
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 || !nameRE.MatchString(name) {
		return "", ErrInvalidName
	}
	return strings.ToLower(name), nil
}

// Challenge checks a /present or /cleanup request against the names
// allowed for the client. allowed must contain names normalized by
// NormalizeName. It returns the name the challenge is for, taken from the
// allowed list.
//
// The name is checked before the value: a client asking for a name it is
// not entitled to always gets ErrNotAllowed, whatever the value.
//
// Lowercasing before the comparison is safe here: the result must be equal
// to a name in the allowed list, which only contains validated ASCII names.
func Challenge(fqdn, value string, allowed []string) (string, error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	fqdn = strings.ToLower(fqdn)

	rest, ok := strings.CutPrefix(fqdn, "_acme-challenge.")
	if !ok {
		return "", ErrNotAllowed
	}
	if !slices.Contains(allowed, rest) {
		return "", ErrNotAllowed
	}
	if !valueRE.MatchString(value) {
		return "", ErrInvalidValue
	}
	return rest, nil
}
