// Package edge is the TLS front that runs on every VM. It terminates HTTPS
// with the CA-issued IP certificate, checks the lease header, and forwards
// /p/<port>/... to agentctl on 127.0.0.1:<port>. agentctl itself listens on
// loopback only (AGENTCTL_LISTEN_HOST=127.0.0.1).
package edge

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/lease"
)

// Config is /etc/hostd-edge/edge.json. It holds no secrets; the lease key
// and TLS key are separate 0600 files.
type Config struct {
	Resource     string `json:"resource"`
	Listen       string `json:"listen"`
	ControlPort  uint32 `json:"control_port"`
	InstanceBase uint32 `json:"instance_port_base"`
	InstanceMax  uint32 `json:"instance_port_max"`
	// Relay, when set, also serves the loopback Git credential broker relay
	// (relay.go).
	Relay *RelayConfig `json:"relay,omitempty"`
}

// Files inside the edge directory.
const (
	ConfigFile  = "edge.json"
	LeaseKey    = "lease.key"
	TLSKeyFile  = "tls.key"
	TLSCertFile = "tls.crt"
)

// Server is the edge HTTP handler plus certificate loader.
type Server struct {
	Dir  string
	Cfg  Config
	key  []byte
	now  func() time.Time
	mu   sync.Mutex
	cert *tls.Certificate
	mod  time.Time
}

// Load reads the edge directory.
func Load(dir string) (*Server, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	key, err := os.ReadFile(filepath.Join(dir, LeaseKey))
	if err != nil {
		return nil, err
	}
	if len(key) < 32 {
		return nil, errors.New("edge: lease key too short")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8443"
	}
	return &Server{Dir: dir, Cfg: cfg, key: key, now: time.Now}, nil
}

// NewForTest builds a server without files.
func NewForTest(cfg Config, key []byte, now func() time.Time) *Server {
	return &Server{Cfg: cfg, key: key, now: now}
}

// GetCertificate reloads tls.crt when it changes, so a renewed leaf takes
// effect without a restart.
func (s *Server) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certPath := filepath.Join(s.Dir, TLSCertFile)
	info, err := os.Stat(certPath)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cert != nil && info.ModTime().Equal(s.mod) {
		return s.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(certPath, filepath.Join(s.Dir, TLSKeyFile))
	if err != nil {
		return nil, err
	}
	s.cert, s.mod = &pair, info.ModTime()
	return s.cert, nil
}

func (s *Server) portAllowed(p uint32) bool {
	return p == s.Cfg.ControlPort || (s.Cfg.InstanceBase > 0 && p >= s.Cfg.InstanceBase && p <= s.Cfg.InstanceMax)
}

// ServeHTTP routes /p/<port>/rest to 127.0.0.1:<port>/rest after checking
// the lease. The lease header is removed before forwarding; Authorization
// (agentctl's own bearer token) and X-Instance-ID pass through untouched.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	port, rest, ok := splitPortPath(r.URL.Path)
	if !ok || !s.portAllowed(port) {
		http.NotFound(w, r)
		return
	}
	if _, err := lease.Verify(s.key, r.Header.Get(lease.Header), s.Cfg.Resource, port, s.now()); err != nil {
		http.Error(w, "lease rejected", http.StatusUnauthorized)
		return
	}
	target := &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(int(port))}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = rest
			pr.Out.URL.RawPath = ""
			pr.Out.Header.Del(lease.Header)
			pr.Out.Host = target.Host
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func splitPortPath(p string) (uint32, string, bool) {
	if !strings.HasPrefix(p, "/p/") {
		return 0, "", false
	}
	tail := p[len("/p/"):]
	num, rest, _ := strings.Cut(tail, "/")
	n, err := strconv.ParseUint(num, 10, 16)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != num {
		return 0, "", false
	}
	return uint32(n), "/" + rest, true
}

// ListenAndServe starts HTTPS on Cfg.Listen.
func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.Cfg.Listen,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.GetCertificate},
	}
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("edge: %w", err)
	}
	return nil
}
