// Package auth authenticates acme-proxy clients.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
)

// Client is a client loaded from the configuration.
type Client struct {
	Name      string
	TokenHash [32]byte       // SHA-256 of the client token
	Sources   []netip.Prefix // networks the client may connect from
	Domains   []string       // names normalized by validate.NormalizeName
}

// ErrUnauthorized is returned for every authentication failure. The wrapped
// errors below give the exact reason, for logs only: never send it to clients.
var (
	ErrUnauthorized  = errors.New("unauthorized")
	ErrUnknownClient = fmt.Errorf("%w: unknown client", ErrUnauthorized)
	ErrBadToken      = fmt.Errorf("%w: bad token", ErrUnauthorized)
	ErrBadSource     = fmt.Errorf("%w: source address not allowed", ErrUnauthorized)
)

// HashToken returns the SHA-256 hash of a client token.
func HashToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// Authenticate returns the client matching name and token, if the request
// comes from one of the client's allowed networks.
func Authenticate(clients []Client, name, token string, addr netip.Addr) (Client, error) {
	hash := HashToken(token)

	var found Client
	ok := false
	for _, c := range clients {
		if c.Name == name {
			found = c
			ok = true
			break
		}
	}
	if !ok {
		return Client{}, ErrUnknownClient
	}

	if subtle.ConstantTimeCompare(hash[:], found.TokenHash[:]) != 1 {
		return Client{}, ErrBadToken
	}

	addr = addr.Unmap()
	for _, p := range found.Sources {
		if p.Contains(addr) {
			return found, nil
		}
	}

	return Client{}, ErrBadSource
}
