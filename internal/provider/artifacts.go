package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/kdlbs/kandev/pluginsdk"
)

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FileBlob describes a local file, hashing it once.
func FileBlob(path string) (Blob, error) {
	f, err := os.Open(path)
	if err != nil {
		return Blob{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return Blob{}, err
	}
	return Blob{
		Open:   func(context.Context) (io.ReadCloser, error) { return os.Open(path) },
		SHA256: hex.EncodeToString(h.Sum(nil)), Size: n,
	}, nil
}

// defaultEdgeBinary looks for hostd-edge-linux-amd64 next to the plugin
// executable (it ships in the same plugin package) or at $HOSTD_EDGE_BINARY.
func defaultEdgeBinary() (Blob, error) {
	if p := os.Getenv("HOSTD_EDGE_BINARY"); p != "" {
		return FileBlob(p)
	}
	exe, err := os.Executable()
	if err != nil {
		return Blob{}, err
	}
	return FileBlob(filepath.Join(filepath.Dir(exe), "hostd-edge-linux-amd64"))
}

// hostArtifact streams agentctl from Kandev (ReadExecutorRuntimeArtifact)
// into a digest-named cache file under KANDEV_PLUGIN_DATA_DIR, then serves it
// as a Blob. The host validates sequence, size and SHA-256 while streaming
// (pluginsdk executorArtifactStreamValidator); this re-checks the digest.
func hostArtifact(ctx context.Context, rc *pluginsdk.ExecutorProviderRequestContext, cb pluginsdk.ExecutorProviderHostAPI) (Blob, error) {
	if cb == nil {
		return Blob{}, errors.New("executor provider host callbacks are unavailable")
	}
	dir := os.Getenv("KANDEV_PLUGIN_DATA_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "artifacts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Blob{}, err
	}
	tmp, err := os.CreateTemp(dir, "agentctl-*.part")
	if err != nil {
		return Blob{}, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	var want string
	var size int64
	err = cb.ReadExecutorRuntimeArtifact(ctx, &pluginsdk.ReadExecutorRuntimeArtifactRequest{Context: rc, ArtifactId: "agentctl", Platform: "linux-amd64"},
		func(c *pluginsdk.ExecutorRuntimeArtifactChunk) error {
			if c.GetChunkIndex() == 0 {
				want = c.GetSha256()
			}
			n, err := tmp.Write(c.GetData())
			size += int64(n)
			h.Write(c.GetData())
			return err
		})
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Blob{}, fmt.Errorf("read agentctl artifact: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !hexDigest.MatchString(want) || got != want {
		return Blob{}, errors.New("agentctl artifact digest mismatch")
	}
	final := filepath.Join(dir, "agentctl-"+got)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return Blob{}, err
	}
	return Blob{Open: func(context.Context) (io.ReadCloser, error) { return os.Open(final) }, SHA256: got, Size: size}, nil
}
