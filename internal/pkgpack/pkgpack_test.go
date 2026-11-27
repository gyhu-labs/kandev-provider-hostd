package pkgpack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"
)

const manifest = `id: "demo"
version: "0.1.0"
runtime:
  type: binary
  executables:
    linux-amd64: "server/plugin-linux-amd64"
`

func sample() map[string][]byte {
	return map[string][]byte{
		"manifest.yaml":                 []byte(manifest),
		"server/plugin-linux-amd64":     []byte("\x7fELF plugin"),
		"server/hostd-edge-linux-amd64": []byte("\x7fELF edge"),
		"README.md":                     []byte("readme"),
	}
}

func TestWriteIsReproducibleAndVerifies(t *testing.T) {
	var a, b bytes.Buffer
	mt := time.Unix(1764201600, 0)
	if _, err := Write(&a, sample(), mt); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(&b, sample(), mt); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("same inputs must give identical bytes")
	}
	m, err := Verify(bytes.NewReader(a.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "demo" || m.Version != "0.1.0" {
		t.Fatalf("manifest: %+v", m)
	}
	// Entry modes as Kandev's own builder writes them.
	gz, _ := gzip.NewReader(bytes.NewReader(a.Bytes()))
	tr := tar.NewReader(gz)
	var last string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		last = h.Name
		want := int64(0o644)
		if strings.HasPrefix(h.Name, "server/") {
			want = 0o755
		}
		if h.Mode != want || h.Typeflag != tar.TypeReg {
			t.Errorf("%s: mode %o type %c", h.Name, h.Mode, h.Typeflag)
		}
	}
	if last != ChecksumsFile {
		t.Fatalf("checksums.txt must be the final entry, got %s", last)
	}
}

func TestWriteRejects(t *testing.T) {
	for name, mut := range map[string]func(map[string][]byte){
		"presupplied checksums": func(f map[string][]byte) { f[ChecksumsFile] = []byte("x") },
		"missing executable":    func(f map[string][]byte) { delete(f, "server/plugin-linux-amd64") },
		"missing manifest":      func(f map[string][]byte) { delete(f, ManifestFile) },
		"unsafe path":           func(f map[string][]byte) { f["../evil"] = []byte("x") },
		"backslash":             func(f map[string][]byte) { f["server\\x"] = []byte("x") },
	} {
		f := sample()
		mut(f)
		if _, err := Write(&bytes.Buffer{}, f, time.Unix(0, 0)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Write(&buf, sample(), time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	// Rebuild the archive with one file changed but the old checksums.
	gz, _ := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	tr := tar.NewReader(gz)
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		data := new(bytes.Buffer)
		_, _ = data.ReadFrom(tr)
		b := data.Bytes()
		if h.Name == "README.md" {
			b = []byte("tampered")
			h.Size = int64(len(b))
		}
		_ = tw.WriteHeader(h)
		_, _ = tw.Write(b)
	}
	_ = tw.Close()
	_ = zw.Close()
	if _, err := Verify(&out); err == nil {
		t.Fatal("tampered package verified")
	}
}
