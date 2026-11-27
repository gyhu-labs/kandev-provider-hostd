// This file is copied by CI into a checkout of kdlbs/kandev at the pinned
// release (apps/backend/internal/plugins/pkgtar/) and run there, so the
// plugin package is checked by Kandev's own installer code: Verify (every
// declared executable, checksums, safe paths, manifest validation) and
// Install (the exact extraction the server performs on POST
// /api/plugins/install). It is not part of this module's build: Go ignores
// directories whose name starts with a dot.
package pkgtar

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHostdProviderPackage(t *testing.T) {
	path := os.Getenv("HOSTD_PACKAGE")
	if path == "" {
		t.Skip("HOSTD_PACKAGE is not set")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := Verify(f)
	if err != nil {
		t.Fatalf("Kandev pkgtar.Verify rejected the package: %v", err)
	}
	if res.Manifest.ID != "kandev-provider-hostd" {
		t.Fatalf("unexpected plugin id %q", res.Manifest.ID)
	}
	if want := os.Getenv("HOSTD_VERSION"); want != "" && res.Manifest.Version != want {
		t.Fatalf("manifest version %q, want %q", res.Manifest.Version, want)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	inst, err := Install(f, root)
	if err != nil {
		t.Fatalf("Kandev pkgtar.Install rejected the package: %v", err)
	}
	for _, rel := range []string{"server/plugin-linux-amd64", "server/hostd-edge-linux-amd64", "manifest.yaml"} {
		info, err := os.Stat(filepath.Join(inst.InstallPath, rel))
		if err != nil {
			t.Fatalf("installed package lacks %s: %v", rel, err)
		}
		if rel == "server/plugin-linux-amd64" && info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("plugin executable is not executable after install: %v", info.Mode())
		}
	}
	t.Logf("verified and installed %s %s at %s (signed=%v)", res.Manifest.ID, res.Manifest.Version, inst.InstallPath, res.Signed)
}
