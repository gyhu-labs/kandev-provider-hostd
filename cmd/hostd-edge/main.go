// Command hostd-edge is the per-VM TLS front shipped by the provider.
//
//	hostd-edge csr        --dir /etc/hostd-edge              # create tls.key (0600) if absent, print a CSR
//	hostd-edge relay-init --dir /etc/hostd-edge --host NAME  # VM-local broker relay certificate (edge/relay.go)
//	hostd-edge serve      --dir /etc/hostd-edge              # HTTPS front for agentctl (+ relay if configured)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/edge"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/tlsca"
)

// relayValidity outlives the longest VM (tlsca.MaxLeafLifetime) by a day.
const relayValidity = tlsca.MaxLeafLifetime + 24*time.Hour

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hostd-edge csr|relay-init|serve --dir DIR")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := fs.String("dir", "/etc/hostd-edge", "edge directory")
	host := fs.String("host", "", "relay-init: broker host name agentctl dials")
	_ = fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "csr":
		err = csr(*dir)
	case "relay-init":
		err = relayInit(*dir, *host)
	case "serve":
		err = serve(*dir)
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostd-edge:", err)
		os.Exit(1)
	}
}

func serve(dir string) error {
	s, err := edge.Load(dir)
	if err != nil {
		return err
	}
	if s.Cfg.Relay == nil {
		return s.ListenAndServe()
	}
	relay, err := edge.NewRelay(*s.Cfg.Relay, nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 2)
	go func() { errc <- s.ListenAndServe() }()
	go func() { errc <- edge.ListenAndServeRelay(ctx, dir, relay) }()
	// Either listener ending is fatal; systemd restarts the unit.
	if err := <-errc; err != nil {
		return err
	}
	return errors.New("listener stopped")
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

// relayInit writes relay-ca.crt (public, for the VM trust store), relay.crt
// and relay.key (0600). The anchor's key never touches the disk.
func relayInit(dir, host string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	caPEM, certPEM, keyPEM, err := edge.GenerateRelayCertificate(host, relayValidity)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		mode os.FileMode
		data []byte
	}{{edge.RelayKeyFile, 0o600, keyPEM}, {edge.RelayCertFile, 0o644, certPEM}, {edge.RelayCAFile, 0o644, caPEM}} {
		tmp := filepath.Join(dir, f.name+".new")
		if err := os.WriteFile(tmp, f.data, f.mode); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dir, f.name)); err != nil {
			return err
		}
	}
	return nil
}
