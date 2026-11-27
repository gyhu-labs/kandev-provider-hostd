// Package pkgpack writes and checks Kandev plugin packages in the format
// Kandev's installer accepts (apps/backend/internal/plugins/pkgtar in
// kdlbs/kandev, docs/public/plugins-authoring.md "Package and data layout"):
// a gzip'd tar of regular files with clean relative paths, manifest.yaml,
// the declared server/ executables, and a generated checksums.txt of
// "<sha256-hex>  <path>" lines covering every other file.
//
// Upstream's own packer (cmd/plugin-pack) lives in Kandev's backend module
// and is not importable from another module, so this is a small, byte-level
// reimplementation of pkgtartest.WritePackage. CI additionally verifies the
// result with upstream pkgtar.Verify at the pinned Kandev release.
package pkgpack

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ManifestFile  = "manifest.yaml"
	ChecksumsFile = "checksums.txt"
	SignatureFile = "checksums.txt.sig"
	// Kandev's install caps (pkgtar.go maxPackageFileSize/TotalSize).
	MaxFileSize  = 200 << 20
	MaxTotalSize = 200 << 20
)

// Manifest is the subset of manifest.yaml the packer checks.
type Manifest struct {
	ID      string `yaml:"id"`
	Version string `yaml:"version"`
	Runtime struct {
		Type        string            `yaml:"type"`
		Executables map[string]string `yaml:"executables"`
	} `yaml:"runtime"`
}

// ReadDir collects every regular file under dir as path -> content.
func ReadDir(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("pkgpack: %s is not a regular file", p)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	return files, err
}

// Write packs files into w. mtime is stamped on every entry, so the output
// is byte-for-byte reproducible for the same inputs.
func Write(w io.Writer, files map[string][]byte, mtime time.Time) (*Manifest, error) {
	if _, ok := files[ChecksumsFile]; ok {
		return nil, errors.New("pkgpack: checksums.txt is generated and must not be supplied")
	}
	if _, ok := files[SignatureFile]; ok {
		return nil, errors.New("pkgpack: checksums.txt.sig is not produced by this packer")
	}
	m, err := checkFiles(files)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var sums bytes.Buffer
	for _, n := range names {
		s := sha256.Sum256(files[n])
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), n)
	}
	gz, _ := gzip.NewWriterLevel(w, gzip.BestCompression)
	gz.ModTime = time.Time{}
	tw := tar.NewWriter(gz)
	put := func(name string, data []byte) error {
		mode := int64(0o644)
		if strings.HasPrefix(name, "server/") {
			mode = 0o755
		}
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(data)),
			ModTime: mtime.UTC(), Uname: "root", Gname: "root", Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	for _, n := range names {
		if err := put(n, files[n]); err != nil {
			return nil, err
		}
	}
	if err := put(ChecksumsFile, sums.Bytes()); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return m, gz.Close()
}

func checkFiles(files map[string][]byte) (*Manifest, error) {
	var total int64
	for n, data := range files {
		if _, err := cleanPath(n); err != nil {
			return nil, err
		}
		if len(data) > MaxFileSize {
			return nil, fmt.Errorf("pkgpack: %s exceeds %d bytes", n, MaxFileSize)
		}
		total += int64(len(data))
	}
	if total > MaxTotalSize {
		return nil, fmt.Errorf("pkgpack: package exceeds %d bytes", MaxTotalSize)
	}
	raw, ok := files[ManifestFile]
	if !ok {
		return nil, errors.New("pkgpack: manifest.yaml is required")
	}
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("pkgpack: manifest.yaml: %w", err)
	}
	if m.ID == "" || m.Version == "" || m.Runtime.Type != "binary" || len(m.Runtime.Executables) == 0 {
		return nil, errors.New("pkgpack: manifest needs id, version and a binary runtime with executables")
	}
	for platform, p := range m.Runtime.Executables {
		clean, err := cleanPath(p)
		if err != nil || clean != p || !strings.HasPrefix(p, "server/") {
			return nil, fmt.Errorf("pkgpack: executable for %s must be a clean server/ path", platform)
		}
		if _, ok := files[p]; !ok {
			return nil, fmt.Errorf("pkgpack: declared executable %s is missing", p)
		}
	}
	return &m, nil
}

// cleanPath mirrors pkgtar.cleanArchivePath.
func cleanPath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\\') || path.IsAbs(name) {
		return "", fmt.Errorf("pkgpack: unsafe path %q", name)
	}
	c := path.Clean(name)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") || c != name {
		return "", fmt.Errorf("pkgpack: unsafe path %q", name)
	}
	return c, nil
}

// Verify re-reads a package the way Kandev's installer does: regular files
// only, safe paths, size caps, checksums.txt present and covering exactly
// every other file, the manifest's executables present.
func Verify(r io.Reader) (*Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("pkgpack: gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("pkgpack: %s is not a regular file", hdr.Name)
		}
		name, err := cleanPath(hdr.Name)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxFileSize+1))
		if err != nil || len(data) > MaxFileSize {
			return nil, fmt.Errorf("pkgpack: %s unreadable or too large", name)
		}
		total += int64(len(data))
		if total > MaxTotalSize {
			return nil, errors.New("pkgpack: package too large")
		}
		files[name] = data
	}
	sums, ok := files[ChecksumsFile]
	if !ok {
		return nil, errors.New("pkgpack: missing checksums.txt")
	}
	want := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("pkgpack: malformed checksums line %q", line)
		}
		want[f[1]] = strings.ToLower(f[0])
	}
	for name, data := range files {
		if name == ChecksumsFile || name == SignatureFile {
			continue
		}
		s := sha256.Sum256(data)
		if want[name] != hex.EncodeToString(s[:]) {
			return nil, fmt.Errorf("pkgpack: checksum missing or wrong for %s", name)
		}
	}
	for name := range want {
		if _, ok := files[name]; !ok {
			return nil, fmt.Errorf("pkgpack: checksums.txt lists missing %s", name)
		}
	}
	delete(files, ChecksumsFile)
	delete(files, SignatureFile)
	return checkFiles(files)
}
