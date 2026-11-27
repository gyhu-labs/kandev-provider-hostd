// Package lease mints and verifies the short-lived connection credentials
// that the hostd-edge TLS front on each VM accepts, and mirrors Kandev's own
// validation of a returned ExecutorConnectionLease.
//
// A token is stateless: v1.<payload>.<mac>, where mac = HMAC-SHA256 over the
// payload with a per-VM key. The plugin derives the per-VM key from its lease
// secret and the operation ID, and pushes it to the VM once at bootstrap. The
// plugin can therefore mint a fresh lease for any runtime port without calling
// the VM, and the edge can verify it without calling back.
package lease

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Header is the request header carrying the token. Kandev forbids lease
// headers named Authorization, Host, Cookie, X-Instance-ID and hop-by-hop
// headers, and sets Authorization itself for agentctl's own token.
const Header = "X-Hostd-Lease"

// Claims bind a token to one resource, one runtime port and an expiry.
type Claims struct {
	Resource   string `json:"r"`
	Port       uint32 `json:"p"`
	Generation string `json:"g"`
	Expires    int64  `json:"e"`
}

// DeriveVMKey derives the per-VM verification key. secret is the plugin's
// lease signing secret; operationID identifies the VM's allocation.
func DeriveVMKey(secret []byte, operationID string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("kandev-provider-hostd/lease-key/v1\x00"))
	mac.Write([]byte(operationID))
	return mac.Sum(nil)
}

// Mint returns a token for claims signed with key.
func Mint(key []byte, c Claims) (string, error) {
	if len(key) < 16 {
		return "", errors.New("lease: key too short")
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("v1." + p))
	return "v1." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Verify checks the MAC, expiry, resource and port. It returns the claims.
func Verify(key []byte, token, resource string, port uint32, now time.Time) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return nil, errors.New("lease: malformed token")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("v1." + parts[1]))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(got, want) {
		return nil, errors.New("lease: bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("lease: malformed payload")
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, errors.New("lease: malformed payload")
	}
	if now.Unix() >= c.Expires {
		return nil, errors.New("lease: expired")
	}
	if c.Resource != resource {
		return nil, errors.New("lease: wrong resource")
	}
	if c.Port != port {
		return nil, errors.New("lease: wrong port")
	}
	return &c, nil
}
