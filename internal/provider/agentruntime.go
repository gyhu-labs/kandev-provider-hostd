package provider

import (
	"fmt"
	"regexp"
	"strings"
)

// Agent runtime on the VM. Kandev starts every managed agent (claude-acp,
// codex-acp, ...) on the execution host as
//
//	npx --yes --prefer-offline --prefix <tmp>/kandev-managed-npm-runtime-<uid> <pkg>@<exact>
//
// (Kandev agents/claude_acp.go BuildCommand, managedruntime
// managed_npm_invocation.go, common/managednpm/npm_project.go), so the VM
// needs Node.js with npm/npx. Kandev's own image installs Node 24 (Dockerfile
// NODE_MAJOR=24); the live v0.103.1-gyhu.2 pod runs node v24.22.3 with npm
// 11.19.1, which is the official tarball pinned here.
const (
	NodeVersion = "v24.22.3"
	// sha256 of node-v24.22.3-linux-x64.tar.{xz,gz} from
	// https://nodejs.org/dist/v24.22.3/SHASUMS256.txt, whose detached
	// signature SHASUMS256.txt.asc verified against nodejs/release-keys
	// (key 5BE8A3F6C8A5C01D106C0AD820B1A390B168D356, Antoine du Hamel).
	nodeSHA256TarXZ = "4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb"
	nodeSHA256TarGZ = "061ec3e3062115705b56b51fa9cc330ab50d34b6969387d4e4b1a50c6809acc2"
	nodeDistBase    = "https://nodejs.org/dist"
	nodeInstallRoot = "/opt/node"

	// DefaultAgentPackages is what Kandev v0.103.1 pins for claude-acp
	// (agents/managed_npm_runtime_versions.json). Bump it with Kandev.
	DefaultAgentPackages = "@agentclientprotocol/claude-agent-acp@0.109.0"
)

// exactPackageSpec accepts only name@X.Y.Z[-pre] (npm names, optional
// scope). The specs are interpolated into a root shell script, so nothing
// outside this grammar may pass.
var exactPackageSpec = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]{0,99}/)?[a-z0-9][a-z0-9._-]{0,99}@[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// ParseAgentPackages splits a comma/space separated list of exact npm
// package specs. "none" disables the pre-install.
func ParseAgentPackages(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "none" {
		return nil, nil
	}
	var out []string
	for _, s := range strings.Fields(strings.ReplaceAll(raw, ",", " ")) {
		if !exactPackageSpec.MatchString(s) {
			return nil, fmt.Errorf("agent package %q is not an exact name@version", s)
		}
		out = append(out, s)
	}
	return out, nil
}

// agentRuntimeScript installs the pinned Node.js from the official tarball
// (sha256 pinned above, no curl|bash installer) and pre-installs each agent
// package into npx's cache exactly as Kandev's launch will look it up, so the
// agent start runs offline. It runs as root next to the apt step; curl may be
// missing on a fresh image until apt installs it, so it falls back to wget or
// python3 and retries. Every failure exits non-zero with a "node runtime:"
// message.
func agentRuntimeScript(packages []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `set -e
export HOME=/root npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false
V=%[1]s
D=%[2]s/$V
fail() { echo "node runtime: $*" >&2; exit 1; }
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
  elif command -v python3 >/dev/null 2>&1; then python3 -I -c 'import sys,urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "$1" "$2" 2>/dev/null
  else return 1; fi
}
if [ "$("$D/bin/node" --version 2>/dev/null)" != "$V" ]; then
  if command -v xz >/dev/null 2>&1; then ext=tar.xz; sum=%[3]s; tf=J
  else ext=tar.gz; sum=%[4]s; tf=z; fi
  t=$(mktemp -d)
  ok=0
  for i in $(seq 1 40); do
    if fetch "%[5]s/$V/node-$V-linux-x64.$ext" "$t/node.$ext"; then ok=1; break; fi
    sleep 3
  done
  [ "$ok" = 1 ] || fail "download of node-$V-linux-x64.$ext failed"
  echo "$sum  $t/node.$ext" | sha256sum -c --quiet - >/dev/null 2>&1 || fail "node-$V-linux-x64.$ext sha256 mismatch"
  rm -rf "$D.tmp"; mkdir -p "$D.tmp"
  tar -x${tf}f "$t/node.$ext" -C "$D.tmp" --strip-components=1 --no-same-owner || fail "unpacking node failed"
  rm -rf "$D" "$t"; mv "$D.tmp" "$D"
fi
for b in node npm npx corepack; do ln -sf "$D/bin/$b" /usr/local/bin/$b; done
export PATH=/usr/local/bin:$PATH
[ "$(node --version)" = "$V" ] || fail "node --version is not $V"
npx --version >/dev/null 2>&1 || fail "npx --version failed"
`, NodeVersion, nodeInstallRoot, nodeSHA256TarXZ, nodeSHA256TarGZ, nodeDistBase)
	for _, spec := range packages {
		// `npx --package=<spec> -- <cmd>` keys the npx cache directory
		// (~/.npm/_npx/<sha512(spec)[:16]>) by the same package list as
		// Kandev's `npx ... <spec>`, so the launch finds it installed.
		name := spec[:strings.LastIndex(spec, "@")]
		bin := name[strings.LastIndex(name, "/")+1:]
		fmt.Fprintf(&b, `ok=0
for i in 1 2 3; do
  if npx --yes --prefer-offline --package=%[1]s -- sh -c 'command -v %[2]s >/dev/null' >/tmp/npx-warm.log 2>&1; then ok=1; break; fi
  sleep 2
done
[ "$ok" = 1 ] || { tail -c 400 /tmp/npx-warm.log >&2; fail "pre-install of %[1]s failed"; }
`, spec, bin)
		if name == "@agentclientprotocol/claude-agent-acp" {
			// claude-agent-acp spawns the Claude CLI from the SDK's
			// platform package (dist/claude-cli.js) unless
			// CLAUDE_CODE_EXECUTABLE is set; Kandev does not set it.
			fmt.Fprintf(&b, `cli=$(npx --yes --offline --package=%[1]s -- sh -c 'b=$(command -v claude-agent-acp); find "${b%%/.bin/*}" -path "*/@anthropic-ai/claude-agent-sdk-linux-x64/claude" -type f | head -1')
[ -n "$cli" ] && "$cli" --version >/dev/null 2>&1 || fail "Claude CLI of %[1]s is missing or does not run"
`, spec)
		}
	}
	b.WriteString("echo \"node $(node --version) npm $(npm --version)\"\n")
	return b.String()
}
