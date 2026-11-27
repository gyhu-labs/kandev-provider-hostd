package tlsca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"net"
	"testing"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostdnet"
)

var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}

// The production CA is cut for hostdnet.DefaultPermittedCIDRs. This test
// proves, with Go's own verifier, what trusting that CA can and cannot do.
func TestProductionRangesCAProperties(t *testing.T) {
	ca := newCA(t, hostdnet.Split(hostdnet.DefaultPermittedCIDRs)...)

	var critical bool
	for _, ext := range ca.Cert.Extensions {
		if ext.Id.Equal(oidNameConstraints) {
			critical = ext.Critical
		}
	}
	if !critical {
		t.Fatal("NameConstraints extension must be present and critical")
	}
	if !ca.Cert.IsCA || !ca.Cert.MaxPathLenZero || ca.Cert.MaxPathLen != 0 {
		t.Fatal("CA must be pathlen:0 (no intermediates)")
	}

	// In range (both /24s): verifies by IP.
	for _, ip := range []string{"38.56.199.1", "38.56.199.254", "155.133.32.1", "155.133.32.254"} {
		_, leaf, err := ca.IssueLeaf(csr(t), net.ParseIP(ip), time.Hour)
		if err != nil {
			t.Fatalf("issue %s: %v", ip, err)
		}
		if err := VerifyLeaf(ca.Pool(), leaf, ip); err != nil {
			t.Fatalf("in-range leaf %s rejected: %v", ip, err)
		}
	}

	// Out of range: the issuer refuses, and a leaf signed anyway is rejected
	// by the verifier, also inside a pool that holds other roots (as in the
	// SSL_CERT_FILE bundle: system roots + this CA).
	bundle := x509.NewCertPool()
	other := newCA(t, "192.0.2.0/24")
	bundle.AddCert(other.Cert)
	bundle.AddCert(ca.Cert)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, ip := range []string{"38.56.198.255", "38.56.200.1", "155.133.31.255", "155.133.33.1", "1.2.3.4", "10.0.0.1"} {
		if _, _, err := ca.IssueLeaf(csr(t), net.ParseIP(ip), time.Hour); err == nil {
			t.Fatalf("issuer accepted out-of-range %s", ip)
		}
		_, leaf, err := ca.signUnchecked(&key.PublicKey, []net.IP{net.ParseIP(ip)}, nil, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyLeaf(bundle, leaf, ip)
		if _, ok := err.(x509.CertificateInvalidError); !ok || err.(x509.CertificateInvalidError).Reason != x509.CANotAuthorizedForThisName {
			t.Fatalf("out-of-range %s: want CANotAuthorizedForThisName, got %v", ip, err)
		}
	}

	// DNS leaves (the names Kandev talks to) are rejected even inside the bundle.
	for _, name := range []string{"api.github.com", "api.anthropic.com", "kandev.gyhu.me", "localhost"} {
		_, leaf, err := ca.signUnchecked(&key.PublicKey, nil, []string{name}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyLeaf(bundle, leaf, name); err == nil {
			t.Fatalf("DNS leaf %s verified", name)
		}
	}
}

func TestRangesSourceIsIPv4Only(t *testing.T) {
	nets, err := ParseCIDRs(hostdnet.Split(hostdnet.DefaultPermittedCIDRs))
	if err != nil || len(nets) != 2 {
		t.Fatalf("default ranges: %v %v", nets, err)
	}
	for _, n := range nets {
		if n.IP.To4() == nil {
			t.Fatalf("%s: the CA ranges must be IPv4 (VMs are created wan_mode=ipv4)", n)
		}
		if ones, _ := n.Mask.Size(); ones != 24 {
			t.Fatalf("%s: expected an announced /24", n)
		}
	}
	if _, err := ParseCIDRs(hostdnet.Split(hostdnet.IPv6Prefixes)); err != nil {
		t.Fatal(err)
	}
}
