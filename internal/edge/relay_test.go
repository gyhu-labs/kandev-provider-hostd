package edge

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const brokerHost = "kandev-broker.kandev.svc.lab.example.com"

func newTestRelay(t *testing.T, upstream *httptest.Server) *Relay {
	t.Helper()
	client := upstream.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r, err := NewRelay(RelayConfig{Host: brokerHost, Upstream: upstream.URL}, client)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func relayDo(t *testing.T, r *Relay, method, target, host, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Result()
}

func TestRelayForwardsOnlyBrokerRoutes(t *testing.T) {
	var seen []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Error("relay must not forward Authorization, Cookie or forwarding headers")
		}
		switch r.URL.Path {
		case "/api/v1/git/credentials/resolve":
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"echo":`+string(b)+`}`)
		case "/api/v1/git/credentials/reissue":
			_, _ = io.WriteString(w, `{"token":"t"}`)
		default:
			t.Errorf("unexpected upstream path %s", r.URL.Path)
		}
	}))
	defer upstream.Close()
	r := newTestRelay(t, upstream)

	if resp := relayDo(t, r, http.MethodGet, "/api/v1/git/credentials/resolve", brokerHost, "", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("readiness probe: %d", resp.StatusCode)
	}
	resp := relayDo(t, r, http.MethodPost, "/api/v1/git/credentials/resolve", brokerHost+":443", `{"lease":"x"}`,
		map[string]string{"Content-Type": "application/json", "Authorization": "Bearer nope", "Cookie": "a=b", "X-Forwarded-For": "1.2.3.4"})
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != `{"echo":{"lease":"x"}}` || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("resolve: %d %s", resp.StatusCode, body)
	}
	if resp := relayDo(t, r, http.MethodPost, "/api/v1/git/credentials/reissue", brokerHost, `{}`, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("reissue: %d", resp.StatusCode)
	}

	for _, tc := range []struct {
		method, path, host string
		want               int
	}{
		{http.MethodGet, "/api/v1/workspaces", brokerHost, http.StatusNotFound},
		{http.MethodGet, "/api/v1/git/credentials/reissue", brokerHost, http.StatusMethodNotAllowed},
		{http.MethodDelete, "/api/v1/git/credentials/resolve", brokerHost, http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/git/credentials/resolve?x=1", brokerHost, http.StatusNotFound},
		{http.MethodGet, "/api/v1/git/credentials/resolve/../../workspaces", brokerHost, http.StatusNotFound},
		{http.MethodGet, "/api/v1/git/credentials/resolve", "api.github.com", http.StatusMisdirectedRequest},
	} {
		if resp := relayDo(t, r, tc.method, tc.path, tc.host, "", nil); resp.StatusCode != tc.want {
			t.Errorf("%s %s (host %s) = %d, want %d", tc.method, tc.path, tc.host, resp.StatusCode, tc.want)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("upstream saw %v, want exactly the 3 allowed requests", seen)
	}
	big := strings.Repeat("x", relayMaxBody+1)
	if resp := relayDo(t, r, http.MethodPost, "/api/v1/git/credentials/resolve", brokerHost, big, nil); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", resp.StatusCode)
	}
}

func TestRelayDoesNotFollowRedirects(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://login.example/", http.StatusFound)
	}))
	defer upstream.Close()
	resp := relayDo(t, newTestRelay(t, upstream), http.MethodGet, "/api/v1/git/credentials/resolve", brokerHost, "", nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://login.example/" {
		t.Fatalf("redirect must be passed back, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestNewRelayRejectsLoopsAndBadUpstreams(t *testing.T) {
	for _, cfg := range []RelayConfig{
		{Host: "kandev.example.com", Upstream: "https://kandev.example.com"},
		{Host: brokerHost, Upstream: "http://kandev.example.com"},
		{Host: brokerHost, Upstream: "https://kandev.example.com/api"},
		{Host: "", Upstream: "https://kandev.example.com"},
	} {
		if _, err := NewRelay(cfg, nil); err == nil {
			t.Errorf("NewRelay(%+v) accepted", cfg)
		}
	}
}

func TestRelayCertificateIsNameConstrainedToTheBrokerHost(t *testing.T) {
	caPEM, certPEM, keyPEM, err := GenerateRelayCertificate(brokerHost, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || !ca.PermittedDNSDomainsCritical || len(ca.PermittedDNSDomains) != 1 || ca.PermittedDNSDomains[0] != brokerHost || len(ca.ExcludedIPRanges) != 2 {
		t.Fatalf("anchor constraints: %+v %+v", ca.PermittedDNSDomains, ca.ExcludedIPRanges)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	lb, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(lb.Bytes)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: brokerHost, Roots: roots}); err != nil {
		t.Fatalf("relay leaf must verify for the broker host: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "api.github.com", Roots: roots}); err == nil {
		t.Fatal("relay leaf must not verify for another host")
	}
	if _, _, _, err := GenerateRelayCertificate("10.0.0.1", time.Hour); err == nil {
		t.Fatal("an IP must be refused as relay host")
	}
}
