package provider

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/kdlbs/kandev/pluginsdk"
)

func TestParseAgentPackages(t *testing.T) {
	got, err := ParseAgentPackages(DefaultAgentPackages)
	if err != nil || len(got) != 1 || got[0] != "@agentclientprotocol/claude-agent-acp@0.109.0" {
		t.Fatalf("default: %v %v", got, err)
	}
	got, err = ParseAgentPackages(" @agentclientprotocol/claude-agent-acp@0.109.0, @agentclientprotocol/codex-acp@2.8.0 pi-acp@0.0.34-rc.1 ")
	if err != nil || len(got) != 3 {
		t.Fatalf("list: %v %v", got, err)
	}
	if got, err := ParseAgentPackages("none"); err != nil || got != nil {
		t.Fatalf("none: %v %v", got, err)
	}
	// Specs land in a root shell script: only exact name@x.y.z passes.
	for _, bad := range []string{
		"x@latest", "x", "x@^1.0.0", "@scope/x", "x@1.0.0;reboot", "x@1.0.0'$(id)'", "x@1.0.0\nreboot",
		"$(id)@1.0.0", "../x@1.0.0", "X@1.0.0", "x@1.0.0 && reboot",
	} {
		if _, err := ParseAgentPackages(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestAgentRuntimeScript(t *testing.T) {
	s := agentRuntimeScript([]string{DefaultAgentPackages})
	for _, want := range []string{
		"V=" + NodeVersion,
		nodeSHA256TarXZ, nodeSHA256TarGZ,
		"https://nodejs.org/dist/$V/node-$V-linux-x64.$ext",
		"sha256sum -c",
		`npx --version >/dev/null 2>&1 || fail "npx --version failed"`,
		"npx --yes --prefer-offline --package=@agentclientprotocol/claude-agent-acp@0.109.0 -- sh -c 'command -v claude-agent-acp >/dev/null'",
		"claude-agent-sdk-linux-x64/claude",
		"export HOME=/root",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	for _, bad := range []string{"| bash", "|bash", "| sh ", "| sh\n", "nodesource", "%!"} {
		if strings.Contains(s, bad) {
			t.Errorf("script must not contain %q", bad)
		}
	}
	if len(nodeSHA256TarXZ) != 64 || len(nodeSHA256TarGZ) != 64 {
		t.Fatal("pinned node digests must be sha256 hex")
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("script syntax: %v %s", err, out)
		}
	}
	if s2 := agentRuntimeScript(nil); strings.Contains(s2, "--package=") || !strings.Contains(s2, "npx --version") {
		t.Fatal("without packages the script still installs and checks node, and pre-installs nothing")
	}
}

func TestProfileNodeOptions(t *testing.T) {
	f := newFixture(t)
	f.cfg[cfgInstallNode] = "false"
	f.cfg[cfgAgentPackages] = "none"
	prof, errs := ParseProfile(&pluginsdk.ExecutorProfileSnapshot{Config: f.cfg})
	if len(errs) != 0 || prof.InstallNode || prof.AgentPackages != nil {
		t.Fatalf("install_node=false, agent_npm_packages=none: %+v %v", prof, errs)
	}
}

// Plugin lines must reach Kandev at info: go-plugin forwards stderr lines
// at their level only when they are hclog JSON (or carry a [LEVEL] prefix).
func TestLoggerEmitsHCLogJSON(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf)
	LevelLogf(l, hclog.Info)("op=%s vm=%d phase %s %s", "abc", 7, "node_agent_runtime", "12s")
	LevelLogf(l, hclog.Warn)("op=%s bootstrap failed", "abc")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %q", buf.String())
	}
	for i, want := range []struct{ level, msg string }{
		{"info", "op=abc vm=7 phase node_agent_runtime 12s"},
		{"warn", "op=abc bootstrap failed"},
	} {
		var e map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &e); err != nil {
			t.Fatalf("line %d is not JSON: %q", i, lines[i])
		}
		if e["@level"] != want.level || e["@message"] != want.msg || e["@timestamp"] == nil {
			t.Fatalf("line %d: %v", i, e)
		}
	}
	p := New()
	if p.Logf == nil || p.Warnf == nil {
		t.Fatal("New must wire info and warn loggers")
	}
}
