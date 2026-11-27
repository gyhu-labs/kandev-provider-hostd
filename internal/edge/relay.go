package edge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Broker relay
//
// Kandev hands every remote environment ONE Git credential broker URL,
// derived from its global githubCredentialBroker.publicBaseUrl. In a cluster
// where that name is in-cluster only (it serves the Kubernetes executors),
// a hostd VM cannot resolve or reach it. The relay closes that gap without
// changing Kandev: on the VM, /etc/hosts points the broker name at 127.0.0.1,
// the relay terminates TLS there with a VM-local certificate and forwards
// exactly the broker routes to the public origin of the same Kandev.
//
// The relay's trust anchor is a one-off CA generated on the VM whose
// NameConstraints permit only the broker host name. Its private key is never
// written to disk, so nothing can be signed with it after setup, and it is
// trusted only by the VM's own system store.

// Relay files inside the edge directory.
const (
	RelayCertFile = "relay.crt"
	RelayKeyFile  = "relay.key"
	RelayCAFile   = "relay-ca.crt"
)

// relayMaxBody caps request and response bodies (broker payloads are small
// JSON documents).
const relayMaxBody = 64 << 10

// relayRoutes is the complete set of Kandev routes the relay forwards
// (apps/backend/internal/github/controller.go:77-79; anonymous on the Kandev
// side, the lease/capability in the body is the credential,
// internal/auth/httpmw/middleware.go:351-354).
var relayRoutes = map[string]map[string]bool{
	"/api/v1/git/credentials/resolve": {http.MethodGet: true, http.MethodPost: true},
	"/api/v1/git/credentials/reissue": {http.MethodPost: true},
}

// RelayConfig is the optional relay section of edge.json.
type RelayConfig struct {
	// Listen is the loopback address the relay serves on (127.0.0.1:443).
	Listen string `json:"listen"`
	// Host is the broker host name agentctl dials (from Kandev's api_url).
	Host string `json:"host"`
	// Upstream is the public origin of the same Kandev, e.g. https://kandev.example.
	Upstream string `json:"upstream"`
}

// Relay forwards the broker routes to Upstream.
type Relay struct {
	cfg      RelayConfig
	upstream *url.URL
	client   *http.Client
}

// NewRelay validates cfg. client nil means a default client with system
// roots, no redirects and a 30 s timeout.
func NewRelay(cfg RelayConfig, client *http.Client) (*Relay, error) {
	u, err := url.Parse(cfg.Upstream)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, errors.New("edge: relay upstream must be an https origin")
	}
	if cfg.Host == "" || strings.ContainsAny(cfg.Host, "/:@ ") {
		return nil, errors.New("edge: relay host is invalid")
	}
	if strings.EqualFold(u.Hostname(), cfg.Host) {
		return nil, errors.New("edge: relay host equals the upstream host (the relay would loop)")
	}
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
			// A redirect (e.g. a Cloudflare Access login) is an error for the
			// caller to see, never something to follow.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	u.Path = ""
	return &Relay{cfg: cfg, upstream: u, client: client}, nil
}

// ServeHTTP forwards one broker request.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !strings.EqualFold(host, r.cfg.Host) {
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	methods, ok := relayRoutes[req.URL.Path]
	if !ok || req.URL.RawQuery != "" {
		http.NotFound(w, req)
		return
	}
	if !methods[req.Method] {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, relayMaxBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	target := *r.upstream
	target.Path = req.URL.Path
	out, err := http.NewRequestWithContext(req.Context(), req.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Only content negotiation passes through: no cookies, no Authorization,
	// no forwarding headers from the VM.
	for _, h := range []string{"Content-Type", "Accept", "User-Agent"} {
		if v := req.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}
	resp, err := r.client.Do(out)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, relayMaxBody+1))
	if err != nil || len(data) > relayMaxBody {
		http.Error(w, "upstream response invalid", http.StatusBadGateway)
		return
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		w.Header().Set("Location", loc)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(data)
}

// ListenAndServeRelay serves r over TLS with the relay certificate in dir.
func ListenAndServeRelay(ctx context.Context, dir string, r *Relay) error {
	pair, err := tls.LoadX509KeyPair(dir+"/"+RelayCertFile, dir+"/"+RelayKeyFile)
	if err != nil {
		return fmt.Errorf("edge: relay certificate: %w", err)
	}
	listen := r.cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:443"
	}
	srv := &http.Server{
		Addr:              listen,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}},
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("edge: relay: %w", err)
	}
	return nil
}

// GenerateRelayCertificate creates the VM-local trust anchor and the relay's
// server certificate for host. The anchor is a CA with critical
// NameConstraints permitting only host (and its subdomains) and no IP
// address; its key is discarded before returning.
func GenerateRelayCertificate(host string, validity time.Duration) (caPEM, certPEM, keyPEM []byte, err error) {
	if host == "" || net.ParseIP(host) != nil {
		return nil, nil, nil, errors.New("edge: relay host must be a DNS name")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	_, all4, _ := net.ParseCIDR("0.0.0.0/0")
	_, all6, _ := net.ParseCIDR("::/0")
	caTmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "hostd-edge relay anchor (VM-local)"},
		NotBefore:                   now.Add(-5 * time.Minute),
		NotAfter:                    now.Add(validity),
		KeyUsage:                    x509.KeyUsageCertSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{host},
		ExcludedIPRanges:            []*net.IPNet{all4, all6},
		ExcludedEmailAddresses:      []string{""},
		ExcludedURIDomains:          []string{""},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}
