// Package remote runs the VM bootstrap over SSH. hostd has no user-data, so
// everything after "VM created" happens here.
package remote

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Conn is one SSH connection to a VM.
type Conn struct {
	Client      *ssh.Client
	HostKeySHA  string
	sudoPrefix  string
	dialTimeout time.Duration
}

// Dial connects with key auth. pin is the expected host-key SHA256
// fingerprint ("SHA256:..."); when empty the first key is accepted and
// returned (trust on first use: hostd offers no out-of-band host key).
func Dial(ctx context.Context, addr, user string, signer ssh.Signer, pin string) (*Conn, error) {
	var seen string
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = ssh.FingerprintSHA256(key)
			if pin != "" && seen != pin {
				return fmt.Errorf("remote: host key %s does not match pinned %s", seen, pin)
			}
			return nil
		},
		Timeout: 5 * time.Second,
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	c, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	conn := &Conn{Client: ssh.NewClient(c, chans, reqs), HostKeySHA: seen}
	if user != "root" {
		conn.sudoPrefix = "sudo -n "
	}
	return conn, nil
}

// WaitDial retries Dial until it succeeds or ctx ends.
func WaitDial(ctx context.Context, addr, user string, signer ssh.Signer, pin string, every time.Duration) (*Conn, int, error) {
	attempts := 0
	for {
		attempts++
		attemptCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		conn, err := Dial(attemptCtx, addr, user, signer, pin)
		cancel()
		if err == nil {
			return conn, attempts, nil
		}
		if strings.Contains(err.Error(), "does not match pinned") {
			return nil, attempts, err
		}
		select {
		case <-ctx.Done():
			return nil, attempts, fmt.Errorf("remote: ssh not ready after %d attempts: %w", attempts, err)
		case <-time.After(every):
		}
	}
}

// Close closes the connection.
func (c *Conn) Close() error { return c.Client.Close() }

// Run executes a shell script as root (via sudo -n for non-root users).
// Secrets must never appear in script; pass them on stdin.
func (c *Conn) Run(ctx context.Context, script string, stdin io.Reader) (string, error) {
	s, err := c.Client.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	if stdin != nil {
		s.Stdin = stdin
	}
	// The script travels base64-encoded in the command so quoting is never an
	// issue; it contains no secrets by construction.
	cmd := c.sudoPrefix + "sh -c \"$(echo " + base64.StdEncoding.EncodeToString([]byte(script)) + " | base64 -d)\""
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = s.Signal(ssh.SIGKILL)
		return out.String(), ctx.Err()
	case err := <-done:
		if err != nil {
			return out.String(), fmt.Errorf("remote: %w: %s", err, tail(errb.String(), 600))
		}
		return out.String(), nil
	}
}

// WriteFile writes data to path with mode via stdin (never via argv).
// compress gzips the stream on the wire.
func (c *Conn) WriteFile(ctx context.Context, path string, mode uint32, data io.Reader, compress bool) error {
	if strings.ContainsAny(path, "'\"$`\\ \n") {
		return errors.New("remote: unsafe path")
	}
	dir := path[:strings.LastIndex(path, "/")]
	reader := data
	decoder := "cat"
	if compress {
		pr, pw := io.Pipe()
		go func() {
			gz, _ := gzip.NewWriterLevel(pw, gzip.BestSpeed)
			_, err := io.Copy(gz, data)
			if err == nil {
				err = gz.Close()
			}
			_ = pw.CloseWithError(err)
		}()
		reader = pr
		decoder = "gzip -dc"
	}
	script := fmt.Sprintf("set -e; umask 077; mkdir -p '%s'; %s > '%s.tmp'; chmod %o '%s.tmp'; mv -f '%s.tmp' '%s'",
		dir, decoder, path, mode, path, path, path)
	_, err := c.Run(ctx, script, reader)
	return err
}

// SHA256Hex of a remote file.
func (c *Conn) SHA256Hex(ctx context.Context, path string) (string, error) {
	out, err := c.Run(ctx, "sha256sum '"+path+"' 2>/dev/null | cut -d' ' -f1", nil)
	return strings.TrimSpace(out), err
}

// Fingerprint is a short non-secret digest used to detect a changed value
// on the VM without storing the value.
func Fingerprint(v string) string {
	sum := sha256.Sum256([]byte("kandev-provider-hostd/fp\x00" + v))
	return fmt.Sprintf("%x", sum[:12])
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
