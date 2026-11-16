// Package cloudflare publishes ACME DNS-01 challenge records through the
// Cloudflare API (v4).
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultBaseURL is the Cloudflare API endpoint. Tests point the client at a
// local fake server instead.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

const (
	recordTTL           = 60      // seconds, the minimum Cloudflare accepts
	maxResponseBytes    = 1 << 20 // 1 MiB; real responses are a few KiB
	httpTimeout         = 30 * time.Second
	codeIdenticalRecord = 81058 // "An identical record already exists."
)

var (
	ErrInvalidZoneID = errors.New("invalid zone ID")
	ErrEmptyToken    = errors.New("empty API token")
)

// Zone IDs are 32 lowercase hex characters. The ID ends up in the URL path,
// so it must be validated: "../" in it would send our token to another API
// endpoint.
var zoneIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Client manages TXT records in one Cloudflare zone. It implements the
// server.DNS interface.
type Client struct {
	baseURL string
	zoneID  string
	token   string
	http    *http.Client
}

// New returns a client for the zone with the given ID. The token needs only
// the Zone / DNS / Edit permission on that zone.
func New(zoneID, token string) (*Client, error) {

	if !zoneIDRE.MatchString(zoneID) {
		return nil, ErrInvalidZoneID
	}

	if token == "" {
		return nil, ErrEmptyToken
	}

	return &Client{
		baseURL: DefaultBaseURL,
		zoneID:  zoneID,
		token:   token,
		http: &http.Client{
			Timeout: httpTimeout,
		},
	}, nil
}

// Message is one entry of the "errors" array in a Cloudflare response.
type Message struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// APIError is returned when Cloudflare answers with an error.
type APIError struct {
	StatusCode int
	Errors     []Message
}

func (e *APIError) Error() string {

	s := fmt.Sprintf("cloudflare: HTTP %d", e.StatusCode)
	for _, m := range e.Errors {
		s += fmt.Sprintf("; %d: %s", m.Code, m.Message)
	}
	return s
}

// hasCode reports whether Cloudflare returned the given error code.
func (e *APIError) hasCode(code int) bool {

	for _, m := range e.Errors {
		if m.Code == code {
			return true
		}
	}
	return false
}

// envelope is the wrapper around every Cloudflare response.
type envelope struct {
	Success bool            `json:"success"`
	Errors  []Message       `json:"errors"`
	Result  json.RawMessage `json:"result"` // decoded later, its shape depends on the call
}

// record is a DNS record as the API represents it.
type record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

// do sends one request to the zone's API. path is relative to the zone
// (e.g. "/dns_records"). If in is not nil it is sent as the JSON body; if out
// is not nil the "result" field of the response is decoded into it.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {

	u := c.baseURL + "/zones/" + c.zoneID + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var body io.Reader

	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("cloudflare: %w", err)
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	defer resp.Body.Close()

	var env envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&env); err != nil {
		return fmt.Errorf("cloudflare: HTTP %d: invalid response: %w", resp.StatusCode, err)
	}

	if !env.Success || resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{StatusCode: resp.StatusCode, Errors: env.Errors}
	}

	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("cloudflare: invalid result: %w", err)
		}
	}

	return nil
}

// challengeName returns the name of the challenge record for a domain.
func challengeName(name string) string {

	return "_acme-challenge." + name
}

// Present creates the TXT record "_acme-challenge.<name>" with the given value.
// Creating a record that already exists is not an error, so retries are safe.
func (c *Client) Present(ctx context.Context, name, value string) error {

	rec := record{
		Type:    "TXT",
		Name:    challengeName(name),
		Content: `"` + value + `"`,
		TTL:     recordTTL,
	}

	err := c.do(ctx, http.MethodPost, "/dns_records", nil, rec, nil)

	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.hasCode(codeIdenticalRecord) {
		return nil
	}

	return err
}

// Cleanup deletes the TXT record "_acme-challenge.<name>" with the given value.
// Other records, including other challenges for the same name, are left alone.
// Deleting a record that does not exist is not an error.
func (c *Client) Cleanup(ctx context.Context, name, value string) error {

	fqdn := challengeName(name)

	q := url.Values{}
	q.Set("type", "TXT")
	q.Set("name.exact", fqdn)
	q.Set("per_page", "100")

	var records []record
	if err := c.do(ctx, http.MethodGet, "/dns_records", q, nil, &records); err != nil {
		return err
	}

	for _, r := range records {
		if r.Type != "TXT" || !strings.EqualFold(r.Name, fqdn) || r.Content != value && r.Content != `"`+value+`"` {
			continue
		}
		if err := c.do(ctx, http.MethodDelete, "/dns_records/"+url.PathEscape(r.ID), nil, nil, nil); err != nil {
			return err
		}
	}

	return nil
}
