// Command hostd-edge is the per-VM TLS front shipped by the provider.
//
//	hostd-edge csr   --dir /etc/hostd-edge   # create tls.key (0600) if absent, print a CSR
//	hostd-edge serve --dir /etc/hostd-edge   # HTTPS front for agentctl
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/edge"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/tlsca"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hostd-edge csr|serve --dir DIR")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := fs.String("dir", "/etc/hostd-edge", "edge directory")
	_ = fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "csr":
		err = csr(*dir)
	case "serve":
		var s *edge.Server
		if s, err = edge.Load(*dir); err == nil {
			err = s.ListenAndServe()
		}
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostd-edge:", err)
		os.Exit(1)
	}
}

func csr(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyPEM, csrPEM, err := tlsca.NewKeyAndCSR()
	if err != nil {
		return err
	}
	// Always rotate the key with a new CSR, so a cert is never re-issued for an old key.
	tmp := filepath.Join(dir, edge.TLSKeyFile+".new")
	if err := os.WriteFile(tmp, keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, edge.TLSKeyFile+".pending")); err != nil {
		return err
	}
	_, err = os.Stdout.Write(csrPEM)
	return err
}
