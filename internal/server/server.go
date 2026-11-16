// Package server implements the HTTP API of acme-proxy: the /present and
// /cleanup endpoints of the lego httpreq protocol.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/marcobonomi/acme-proxy/internal/auth"
	"github.com/marcobonomi/acme-proxy/internal/validate"
)

// DNS publishes and removes ACME challenge TXT records. name is a validated
// domain name (e.g. "app1.example.com"); the implementation is responsible for
// adding the "_acme-challenge." prefix.
type DNS interface {
	Present(ctx context.Context, name, value string) error
	Cleanup(ctx context.Context, name, value string) error
}

// Server handles challenge requests.
type Server struct {
	Clients func() []auth.Client
	DNS     DNS
	Log     *slog.Logger
}

const (
	maxBodyBytes = 1024             // a valid request is about 150 bytes
	dnsTimeout   = 25 * time.Second // must be shorter than the server WriteTimeout
)

type action string

const (
	actionPresent action = "present"
	actionCleanup action = "cleanup"
)

// challengeRequest is the JSON body sent by lego's httpreq provider.
type challengeRequest struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

// Handler returns the HTTP handler with the two endpoints.
// Requests with another method get 405, other paths get 404.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /present", s.handle(actionPresent))
	mux.HandleFunc("POST /cleanup", s.handle(actionCleanup))
	return mux
}

// NewHTTPServer returns an http.Server with timeouts suitable for a service
// exposed to untrusted clients.
func NewHTTPServer(addr string, h http.Handler) *http.Server {

	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

// handle returns the handler for one action.
func (s *Server) handle(act action) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			s.Log.Warn("unparsable remote address", "remote", r.RemoteAddr)
			unauthorized(w)
			return
		}

		addr := ap.Addr()

		log := s.Log.With("action", string(act), "remote", addr.String())

		user, token, ok := r.BasicAuth()
		if !ok {
			log.Warn("rejected", "reason", "missing basic auth")
			unauthorized(w)
			return
		}

		client, err := auth.Authenticate(s.Clients(), user, token, addr)
		if err != nil {
			log.Warn("rejected", "user", user, "reason", err)
			unauthorized(w)
			return
		}
		log = log.With("client", client.Name)

		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req challengeRequest
		if err := dec.Decode(&req); err != nil {
			log.Warn("rejected", "reason", "invalid body", "error", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			log.Warn("rejected", "reason", "trailing data", "error", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		name, err := validate.Challenge(req.FQDN, req.Value, client.Domains)
		if err != nil {
			log.Warn("rejected", "reason", err, "fqdn", req.FQDN)
			code := http.StatusBadRequest
			if errors.Is(err, validate.ErrNotAllowed) {
				code = http.StatusForbidden
			}
			http.Error(w, http.StatusText(code), code)
			return
		}
		log = log.With("name", name)

		ctx, cancel := context.WithTimeout(r.Context(), dnsTimeout)
		defer cancel()
		if act == actionPresent {
			err = s.DNS.Present(ctx, name, req.Value)
		} else {
			err = s.DNS.Cleanup(ctx, name, req.Value)
		}
		if err != nil {
			log.Error("dns failed", "error", err)
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}

		log.Info("done")
		w.WriteHeader(http.StatusOK)
	}
}

// unauthorized writes a 401 response that asks for Basic authentication.
func unauthorized(w http.ResponseWriter) {

	w.Header().Set("WWW-Authenticate", `Basic realm="acme-proxy"`)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
