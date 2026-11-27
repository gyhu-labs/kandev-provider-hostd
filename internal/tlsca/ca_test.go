package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newCA(t *testing.T, cidrs ...string) *CA {
	t.Helper()
	nets, err := ParseCIDRs(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := GenerateCA("test CA", nets, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := Load(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func csr(t *testing.T) []byte {
	t.Helper()
	_, c, err := NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLeafInsideConstraintVerifiesByIP(t *testing.T) {
	ca := newCA(t, "38.56.199.0/24")
	_, leaf, err := ca.IssueLeaf(csr(t), net.ParseIP("38.56.199.191"), 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLeaf(ca.Pool(), leaf, "38.56.199.191"); err != nil {
		t.Fatalf("leaf inside the constraint must verify: %v", err)
	}
	if err := VerifyLeaf(ca.Pool(), leaf, "38.56.199.192"); err == nil {
		t.Fatal("leaf must not verify for a different IP")
	}
}

func TestLeafOutsideConstraintIsRejectedByVerifier(t *testing.T) {
	ca := newCA(t, "38.56.199.0/24")
	if _, _, err := ca.IssueLeaf(csr(t), net.ParseIP("1.2.3.4"), time.Hour); err == nil {
		t.Fatal("IssueLeaf must refuse an IP outside the constraint")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, leaf, err := ca.signUnchecked(&key.PublicKey, []net.IP{net.ParseIP("1.2.3.4")}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyLeaf(ca.Pool(), leaf, "1.2.3.4")
	var invalid x509.CertificateInvalidError
	if err == nil || !asInvalid(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
		t.Fatalf("verifier must reject an out-of-range IP with CANotAuthorizedForThisName, got %v", err)
	}
}

func TestDNSNamedLeafIsRejectedByVerifier(t *testing.T) {
	ca := newCA(t, "38.56.199.0/24")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, name := range []string{"kandev.example.com", "api.github.com", "localhost"} {
		_, leaf, err := ca.signUnchecked(&key.PublicKey, nil, []string{name}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyLeaf(ca.Pool(), leaf, name)
		var invalid x509.CertificateInvalidError
		if err == nil || !asInvalid(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
			t.Fatalf("%s: verifier must reject a DNS SAN, got %v", name, err)
		}
	}
	// A leaf that mixes an allowed IP with a DNS name is rejected as a whole.
	_, mixed, err := ca.signUnchecked(&key.PublicKey, []net.IP{net.ParseIP("38.56.199.10")}, []string{"evil.example"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLeaf(ca.Pool(), mixed, "38.56.199.10"); err == nil {
		t.Fatal("a leaf with any DNS SAN must be rejected even for its IP")
	}
}

func TestLifetimeCap(t *testing.T) {
	ca := newCA(t, "38.56.199.0/24")
	if _, _, err := ca.IssueLeaf(csr(t), net.ParseIP("38.56.199.5"), MaxLeafLifetime+time.Second); err == nil {
		t.Fatal("leaf lifetime above 7 days must be refused")
	}
	_, leaf, err := ca.IssueLeaf(csr(t), net.ParseIP("38.56.199.5"), MaxLeafLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(ca.Cert.NotAfter) {
		t.Fatal("leaf must not outlive the CA")
	}
}

func TestLoadRefusesUnconstrainedCA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := randomSerial()
	tmpl := &x509.Certificate{SerialNumber: serial, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	_, err := Load(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err == nil || !strings.Contains(err.Error(), "name constraints") {
		t.Fatalf("an unconstrained CA must be refused, got %v", err)
	}
}

// TestTLSHandshakeWithOnlyThisCA runs a real HTTPS handshake to an IP literal
// with a client whose RootCAs contain only the constrained CA.
func TestTLSHandshakeWithOnlyThisCA(t *testing.T) {
	ca := newCA(t, "127.0.0.0/8")
	keyPEM, csrPEM, err := NewKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, _, err := ca.IssueLeaf(csrPEM, net.ParseIP("127.0.0.1"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12}}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("handshake against the constrained CA failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("unexpected body %q", body)
	}
	// The same server is untrusted for a client using system roots.
	if _, err := http.Get(srv.URL); err == nil {
		t.Fatal("system roots must not trust the private CA")
	}
}

func asInvalid(err error, target *x509.CertificateInvalidError) bool {
	for err != nil {
		if e, ok := err.(x509.CertificateInvalidError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
