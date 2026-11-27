package lease

import (
	"strings"
	"testing"
	"time"
)

func validLease(now time.Time) Lease {
	return Lease{
		BaseURL:          "https://38.56.199.191:8443/p/8765",
		HTTPHeaders:      map[string]string{Header: "v1.x.y"},
		WebSocketHeaders: map[string]string{Header: "v1.x.y"},
		ExpiresAt:        now.Add(10 * time.Minute).UTC().Format(time.RFC3339Nano),
		Generation:       "hostd-1",
	}
}

func TestKandevRulesAcceptProviderLease(t *testing.T) {
	now := time.Now()
	if err := ValidateForKandev(validLease(now), now); err != nil {
		t.Fatal(err)
	}
	// Private addresses are allowed by Kandev (only loopback/link-local/multicast are not).
	l := validLease(now)
	l.BaseURL = "https://10.0.0.5:8443/p/8765"
	if err := ValidateForKandev(l, now); err != nil {
		t.Fatalf("RFC1918 must pass: %v", err)
	}
}

func TestKandevRulesRejections(t *testing.T) {
	now := time.Now()
	cases := map[string]func(*Lease){
		"http":            func(l *Lease) { l.BaseURL = "http://38.56.199.191:8443" },
		"loopback":        func(l *Lease) { l.BaseURL = "https://127.0.0.1:8443" },
		"ipv6 loopback":   func(l *Lease) { l.BaseURL = "https://[::1]:8443" },
		"link-local":      func(l *Lease) { l.BaseURL = "https://169.254.169.254" },
		"multicast":       func(l *Lease) { l.BaseURL = "https://224.0.0.1" },
		"unspecified":     func(l *Lease) { l.BaseURL = "https://0.0.0.0:8443" },
		"userinfo":        func(l *Lease) { l.BaseURL = "https://u:p@38.56.199.191" },
		"fragment":        func(l *Lease) { l.BaseURL = "https://38.56.199.191/#x" },
		"query token":     func(l *Lease) { l.BaseURL = "https://38.56.199.191/?access_token=x" },
		"query sig":       func(l *Lease) { l.BaseURL = "https://38.56.199.191/?X-Signature=x" },
		"bad port":        func(l *Lease) { l.BaseURL = "https://38.56.199.191:0" },
		"authorization":   func(l *Lease) { l.HTTPHeaders = map[string]string{"authorization": "Bearer x"} },
		"x-instance-id":   func(l *Lease) { l.WebSocketHeaders = map[string]string{"X-Instance-Id": "x"} },
		"proxy header":    func(l *Lease) { l.HTTPHeaders = map[string]string{"Proxy-Foo": "x"} },
		"ctl char":        func(l *Lease) { l.HTTPHeaders = map[string]string{Header: "a\nb"} },
		"no generation":   func(l *Lease) { l.Generation = "" },
		"long generation": func(l *Lease) { l.Generation = strings.Repeat("g", 129) },
		"expires soon":    func(l *Lease) { l.ExpiresAt = now.Add(29 * time.Second).Format(time.RFC3339Nano) },
		"bad expiry":      func(l *Lease) { l.ExpiresAt = "tomorrow" },
		"header budget":   func(l *Lease) { l.HTTPHeaders = map[string]string{Header: strings.Repeat("a", HeaderLimit)} },
		"bad subprotocol": func(l *Lease) { l.WebSocketSubprotocols = []string{"a b"} },
	}
	for name, mutate := range cases {
		l := validLease(now)
		mutate(&l)
		if err := ValidateForKandev(l, now); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestTokenRoundTrip(t *testing.T) {
	key := DeriveVMKey([]byte("0123456789abcdef0123456789abcdef"), "op-1")
	now := time.Now()
	tok, err := Mint(key, Claims{Resource: "hostd:p:1", Port: 8765, Generation: "g1", Expires: now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(key, tok, "hostd:p:1", 8765, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(key, tok, "hostd:p:1", 41001, now); err == nil {
		t.Fatal("token must be bound to its port")
	}
	if _, err := Verify(key, tok, "hostd:p:2", 8765, now); err == nil {
		t.Fatal("token must be bound to its resource")
	}
	if _, err := Verify(key, tok, "hostd:p:1", 8765, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired token must fail")
	}
	other := DeriveVMKey([]byte("0123456789abcdef0123456789abcdef"), "op-2")
	if _, err := Verify(other, tok, "hostd:p:1", 8765, now); err == nil {
		t.Fatal("another VM's key must not verify")
	}
	if _, err := Verify(key, tok[:len(tok)-2]+"AA", "hostd:p:1", 8765, now); err == nil {
		t.Fatal("tampered MAC must fail")
	}
}
