package lease

import (
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// These rules mirror Kandev's acceptance checks for a provider lease
// (apps/backend/internal/agent/runtime/agentctl/endpoint_transport.go,
// validateConnectionLease, parseLeaseEndpoint, validateLeaseLifetime,
// normalizeLeaseHeaders, validateResolvedAddresses; Kandev v0.103.1). The
// provider runs them before returning a lease so a contract drift shows up
// in this repo's tests instead of as an opaque launch failure.

// RefreshWindow is Kandev's connectionLeaseRefreshWindow: a lease must
// outlive now+30s or Kandev rejects it as "expires too soon".
const RefreshWindow = 30 * time.Second

// HeaderLimit is Kandev's connectionLeaseHeaderLimit (16 KiB).
const HeaderLimit = 16 * 1024

// Lease is the provider-side view of pluginv1.ExecutorConnectionLease.
type Lease struct {
	BaseURL               string
	HTTPHeaders           map[string]string
	WebSocketHeaders      map[string]string
	WebSocketSubprotocols []string
	ExpiresAt             string
	Generation            string
}

// ValidateForKandev returns the first rule Kandev would reject the lease on.
func ValidateForKandev(l Lease, now time.Time) error {
	if err := validateEndpoint(l.BaseURL); err != nil {
		return err
	}
	if l.Generation == "" || len(l.Generation) > 128 {
		return errors.New("lease has an invalid generation")
	}
	expires, err := time.Parse(time.RFC3339Nano, l.ExpiresAt)
	if err != nil {
		return errors.New("lease expiry is invalid")
	}
	if !expires.After(now.Add(RefreshWindow)) {
		return errors.New("lease is expired or expires too soon")
	}
	used := 0
	for _, set := range []map[string]string{l.HTTPHeaders, l.WebSocketHeaders} {
		n, err := checkHeaders(set)
		if err != nil {
			return err
		}
		used += n
	}
	for _, p := range l.WebSocketSubprotocols {
		if !isHTTPToken(p) {
			return errors.New("lease contains an invalid WebSocket subprotocol")
		}
		used += len(p)
	}
	if used > HeaderLimit {
		return errors.New("lease headers exceed 16 KiB")
	}
	return nil
}

func validateEndpoint(raw string) error {
	if len(raw) > 8192 {
		return errors.New("endpoint is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return errors.New("endpoint is invalid")
	}
	if u.Scheme != "https" {
		return errors.New("endpoint must use HTTPS")
	}
	if u.Host == "" || u.Opaque != "" {
		return errors.New("endpoint is missing a hostname")
	}
	if u.User != nil {
		return errors.New("endpoint cannot contain userinfo")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("endpoint cannot contain a fragment")
	}
	if err := rejectCredentialQuery(u.RawQuery); err != nil {
		return err
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("endpoint has an invalid port")
		}
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return errors.New("endpoint has an invalid hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		if err := ProhibitedAddress(ip); err != nil {
			return err
		}
	}
	return nil
}

// ProhibitedAddress mirrors validateResolvedAddresses. Note that Kandev
// allows private (RFC 1918) addresses; only loopback, link-local,
// multicast and unspecified are refused.
func ProhibitedAddress(ip net.IP) error {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("endpoint resolves to a prohibited address")
	}
	return nil
}

func rejectCredentialQuery(rawQuery string) error {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return errors.New("endpoint has an invalid query")
	}
	for key := range q {
		n := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		switch n {
		case "token", "access_token", "refresh_token", "auth", "authorization", "api_key", "apikey", "key", "secret", "password", "signature", "sig", "credential", "credentials":
			return errors.New("endpoint query cannot contain credentials")
		}
		for _, frag := range []string{"token", "secret", "signature", "credential", "password"} {
			if strings.Contains(n, frag) {
				return errors.New("endpoint query cannot contain credentials")
			}
		}
	}
	return nil
}

func checkHeaders(h map[string]string) (int, error) {
	seen := map[string]bool{}
	total := 0
	for name, value := range h {
		c := textproto.CanonicalMIMEHeaderKey(name)
		if c == "" || !isHTTPToken(c) {
			return 0, errors.New("header name is invalid")
		}
		lower := strings.ToLower(c)
		switch lower {
		case "authorization", "x-instance-id", "host", "cookie", "set-cookie", "sec-websocket-protocol",
			"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
			return 0, fmt.Errorf("provider cannot override %s", c)
		}
		if strings.HasPrefix(lower, "proxy-") {
			return 0, fmt.Errorf("provider cannot override %s", c)
		}
		if seen[lower] {
			return 0, errors.New("header name is duplicated")
		}
		seen[lower] = true
		for _, r := range value {
			if (r < 32 && r != '\t') || r == 127 {
				return 0, fmt.Errorf("header %s has an invalid value", c)
			}
		}
		total += len(c) + 2 + len(value) + 2
	}
	return total, nil
}

func isHTTPToken(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if r <= 32 || r >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", r) {
			return false
		}
	}
	return true
}
