package edge

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/lease"
)

func TestEdgeForwardsOnlyWithValidLease(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(lease.Header) != "" {
			t.Error("lease header must be stripped before agentctl")
		}
		_, _ = io.WriteString(w, r.URL.Path+"|"+r.Header.Get("Authorization"))
	}))
	defer upstream.Close()
	_, portStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	port64, _ := strconv.ParseUint(portStr, 10, 32)
	port := uint32(port64)

	key := lease.DeriveVMKey([]byte("0123456789abcdef0123456789abcdef"), "op")
	now := time.Now()
	s := NewForTest(Config{Resource: "res", ControlPort: port}, key, func() time.Time { return now })
	front := httptest.NewServer(s)
	defer front.Close()

	tok, _ := lease.Mint(key, lease.Claims{Resource: "res", Port: port, Generation: "g", Expires: now.Add(time.Minute).Unix()})
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/p/"+portStr+"/health", nil)
	req.Header.Set(lease.Header, tok)
	req.Header.Set("Authorization", "Bearer agentctl-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "/health|Bearer agentctl-token" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}

	for name, mut := range map[string]func(*http.Request){
		"no lease":     func(r *http.Request) { r.Header.Del(lease.Header) },
		"other port":   func(r *http.Request) { r.URL.Path = "/p/1/health" },
		"not prefixed": func(r *http.Request) { r.URL.Path = "/health" },
		"leading zero": func(r *http.Request) { r.URL.Path = "/p/0" + portStr + "/health" },
	} {
		r, _ := http.NewRequest(http.MethodGet, front.URL+"/p/"+portStr+"/health", nil)
		r.Header.Set(lease.Header, tok)
		mut(r)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Errorf("%s: expected refusal", name)
		}
	}
	_ = port
}
