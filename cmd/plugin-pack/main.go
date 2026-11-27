// Command plugin-pack builds the Kandev plugin package from a staging
// directory, or verifies an existing package.
//
//	plugin-pack -dir .build/stage -out kandev-provider-hostd-0.1.0.tar.gz [-version 0.1.0]
//	plugin-pack -verify kandev-provider-hostd-0.1.0.tar.gz
//
// The entry mtime comes from SOURCE_DATE_EPOCH (else 0) so rebuilding a tag
// gives the same bytes.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/pkgpack"
)

func main() {
	dir := flag.String("dir", "", "staging directory (manifest.yaml, server/...)")
	out := flag.String("out", "", "output .tar.gz")
	version := flag.String("version", "", "require manifest version to equal this (e.g. the tag without v)")
	verify := flag.String("verify", "", "verify an existing package instead of building one")
	flag.Parse()
	if err := run(*dir, *out, *version, *verify); err != nil {
		fmt.Fprintln(os.Stderr, "plugin-pack:", err)
		os.Exit(1)
	}
}

func run(dir, out, version, verify string) error {
	if verify != "" {
		f, err := os.Open(verify)
		if err != nil {
			return err
		}
		defer f.Close()
		m, err := pkgpack.Verify(f)
		if err != nil {
			return err
		}
		if version != "" && m.Version != version {
			return fmt.Errorf("manifest version %s != %s", m.Version, version)
		}
		fmt.Printf("ok %s %s\n", m.ID, m.Version)
		return nil
	}
	if dir == "" || out == "" {
		return errors.New("-dir and -out are required")
	}
	files, err := pkgpack.ReadDir(dir)
	if err != nil {
		return err
	}
	var epoch int64
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		if epoch, err = strconv.ParseInt(s, 10, 64); err != nil {
			return errors.New("SOURCE_DATE_EPOCH is not an integer")
		}
	}
	var buf bytes.Buffer
	m, err := pkgpack.Write(&buf, files, time.Unix(epoch, 0))
	if err != nil {
		return err
	}
	if version != "" && m.Version != version {
		return fmt.Errorf("manifest version %s != %s", m.Version, version)
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(buf.Bytes())
	fmt.Printf("%s  %s\n", hex.EncodeToString(sum[:]), out)
	return nil
}
