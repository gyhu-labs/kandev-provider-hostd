// Command hostd-ca runs the CA ceremony for the provider's name-constrained
// CA (internal/tlsca) and prints a public summary of a CA certificate.
//
//	hostd-ca init --cert ca.crt --key ca.key [--cidrs 38.56.199.0/24,155.133.32.0/24] [--validity 17532h]
//	hostd-ca show --cert ca.crt
//
// init writes the PKCS#8 key with mode 0600 and refuses to overwrite either
// file. It never prints the key. Move the key into the secret store and
// destroy the file (shred -u) right after.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostdnet"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/tlsca"
)

// defaultValidity is about two years (730.5 days).
const defaultValidity = 17532 * time.Hour

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hostd-ca init|show --cert FILE [--key FILE] [--cidrs LIST] [--validity DURATION]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	certPath := fs.String("cert", "", "CA certificate path (PEM)")
	keyPath := fs.String("key", "", "init: CA private key path (PKCS#8 PEM, written 0600)")
	cidrs := fs.String("cidrs", hostdnet.DefaultPermittedCIDRs, "init: permitted IPv4 ranges (comma separated)")
	validity := fs.Duration("validity", defaultValidity, "init: CA validity")
	cn := fs.String("cn", "kandev-provider-hostd CA", "init: subject common name")
	_ = fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "init":
		err = initCA(*certPath, *keyPath, *cidrs, *cn, *validity)
		if err == nil {
			err = show(*certPath)
		}
	case "show":
		err = show(*certPath)
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostd-ca:", err)
		os.Exit(1)
	}
}

func initCA(certPath, keyPath, cidrs, cn string, validity time.Duration) error {
	if certPath == "" || keyPath == "" {
		return errors.New("--cert and --key are required")
	}
	if validity <= 0 || validity > 5*365*24*time.Hour {
		return errors.New("--validity must be in (0, 5y]")
	}
	nets, err := tlsca.ParseCIDRs(hostdnet.Split(cidrs))
	if err != nil {
		return err
	}
	for _, n := range nets {
		if n.IP.To4() == nil {
			return fmt.Errorf("%s: only IPv4 ranges (VMs are IPv4-only)", n)
		}
	}
	certPEM, keyPEM, err := tlsca.GenerateCA(cn, nets, validity)
	if err != nil {
		return err
	}
	// Self-check before anything is written: the pair loads and is constrained.
	if _, err := tlsca.Load(certPEM, keyPEM); err != nil {
		return err
	}
	if err := writeExclusive(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeExclusive(certPath, certPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func show(certPath string) error {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	cert, err := tlsca.ParseCertificatePEM(raw)
	if err != nil {
		return err
	}
	if err := tlsca.CheckConstrained(cert); err != nil {
		return err
	}
	sum := sha256.Sum256(cert.Raw)
	ranges := make([]string, 0, len(cert.PermittedIPRanges))
	for _, n := range cert.PermittedIPRanges {
		ranges = append(ranges, n.String())
	}
	fmt.Printf("subject:            %s\n", cert.Subject)
	fmt.Printf("serial:             %x\n", cert.SerialNumber)
	fmt.Printf("not_before:         %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
	fmt.Printf("not_after:          %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Printf("public_key:         %s\n", cert.PublicKeyAlgorithm)
	fmt.Printf("permitted_ip:       %s\n", strings.Join(ranges, ", "))
	fmt.Printf("excluded_dns:       %q (all names)\n", cert.ExcludedDNSDomains)
	fmt.Printf("constraints_crit:   %v\n", cert.PermittedDNSDomainsCritical)
	fmt.Printf("max_path_len_zero:  %v\n", cert.MaxPathLenZero)
	fmt.Printf("sha256_fingerprint: %s\n", hex.EncodeToString(sum[:]))
	return nil
}
