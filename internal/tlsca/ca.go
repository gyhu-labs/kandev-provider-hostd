// Package tlsca is the provider's offline, name-constrained certificate
// authority. The CA certificate carries critical X.509 NameConstraints that
// permit only the configured iPAddress ranges (hostd public IPv4 blocks) and
// exclude every DNS name, e-mail address and URI. A client that trusts this
// CA therefore cannot be made to accept a certificate for any hostname or for
// an address outside those ranges, even if the CA key leaks. Go's verifier
// (crypto/x509) enforces the constraints at chain-build time.
package tlsca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// MaxLeafLifetime caps every issued leaf (owner decision: at most 7 days).
const MaxLeafLifetime = 7 * 24 * time.Hour

// CA is a parsed CA certificate plus its signing key.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// ParseCIDRs parses a comma-free list of IPv4/IPv6 CIDRs.
func ParseCIDRs(values []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(values))
	for _, v := range values {
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return nil, fmt.Errorf("tlsca: invalid CIDR %q", v)
		}
		nets = append(nets, n)
	}
	if len(nets) == 0 {
		return nil, errors.New("tlsca: at least one permitted CIDR is required")
	}
	return nets, nil
}

// GenerateCA creates a self-signed, name-constrained ECDSA P-256 CA.
func GenerateCA(commonName string, permitted []*net.IPNet, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	if len(permitted) == 0 {
		return nil, nil, errors.New("tlsca: at least one permitted CIDR is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"kandev-provider-hostd"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		// Critical name constraints: IPs only within the permitted ranges;
		// the empty excluded subtree matches every DNS name, mailbox and URI
		// domain, so any such SAN fails verification.
		PermittedDNSDomainsCritical: true,
		PermittedIPRanges:           permitted,
		ExcludedDNSDomains:          []string{""},
		ExcludedEmailAddresses:      []string{""},
		ExcludedURIDomains:          []string{""},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// Load parses a CA certificate and its PKCS#8 key and checks they match and
// that the certificate really carries IP-only constraints.
func Load(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("tlsca: CA key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("tlsca: CA key is not PKCS#8")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlsca: CA key cannot sign")
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("tlsca: CA key does not match the CA certificate")
	}
	if err := CheckConstrained(cert); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: signer}, nil
}

// CheckConstrained refuses a CA without the IP-only constraint set.
func CheckConstrained(cert *x509.Certificate) error {
	if !cert.IsCA || !cert.PermittedDNSDomainsCritical || len(cert.PermittedIPRanges) == 0 {
		return errors.New("tlsca: CA must carry critical IP-only name constraints")
	}
	if len(cert.ExcludedDNSDomains) != 1 || cert.ExcludedDNSDomains[0] != "" || len(cert.PermittedDNSDomains) != 0 {
		return errors.New("tlsca: CA must exclude all DNS names")
	}
	return nil
}

// Permits reports whether ip lies in one of the CA's permitted ranges.
func (ca *CA) Permits(ip net.IP) bool {
	for _, n := range ca.Cert.PermittedIPRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IssueLeaf signs a TLS server certificate for exactly one IP SAN. The key
// comes from a CSR generated on the VM, so the leaf private key never leaves
// the VM. The lifetime is capped at MaxLeafLifetime and at the CA's expiry.
func (ca *CA) IssueLeaf(csrPEM []byte, ip net.IP, lifetime time.Duration) ([]byte, *x509.Certificate, error) {
	if ip == nil {
		return nil, nil, errors.New("tlsca: leaf IP is required")
	}
	if !ca.Permits(ip) {
		return nil, nil, fmt.Errorf("tlsca: %s is outside the CA's permitted ranges", ip)
	}
	if lifetime <= 0 || lifetime > MaxLeafLifetime {
		return nil, nil, fmt.Errorf("tlsca: leaf lifetime must be in (0, %s]", MaxLeafLifetime)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("tlsca: CSR is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, errors.New("tlsca: CSR is invalid")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, errors.New("tlsca: CSR signature is invalid")
	}
	return ca.sign(csr.PublicKey, []net.IP{ip}, nil, lifetime)
}

// signUnchecked issues without the Permits pre-check. Tests use it to prove
// that the verifier, not only this package, rejects out-of-range leaves.
func (ca *CA) signUnchecked(pub crypto.PublicKey, ips []net.IP, dns []string, lifetime time.Duration) ([]byte, *x509.Certificate, error) {
	return ca.sign(pub, ips, dns, lifetime)
}

func (ca *CA) sign(pub crypto.PublicKey, ips []net.IP, dns []string, lifetime time.Duration) ([]byte, *x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	notAfter := now.Add(lifetime)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	cn := "kandev-provider-hostd leaf"
	if len(ips) > 0 {
		cn = ips[0].String()
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

// ParseCertificatePEM parses the first CERTIFICATE block.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("tlsca: certificate is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Pool returns a CertPool holding only this CA.
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// VerifyLeaf verifies leaf for host (an IP literal) against roots only.
func VerifyLeaf(roots *x509.CertPool, leaf *x509.Certificate, host string) error {
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:   host,
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}
