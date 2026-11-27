package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/edge"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/remote"
	"golang.org/x/crypto/ssh"
)

// Agentctl's instance port range on the VM (agentctl defaults; the edge
// forwards only the control port and this range).
const (
	instancePortBase = 41001
	instancePortMax  = 41100
	agentctlPath     = "/usr/local/bin/agentctl"
	edgePath         = "/usr/local/bin/hostd-edge"
	edgeDir          = "/etc/hostd-edge"
)

// Blob is a binary to place on the VM.
type Blob struct {
	Open   func(context.Context) (io.ReadCloser, error)
	SHA256 string
	Size   int64
}

// BootstrapInput is everything the VM bootstrap needs. Secret-bearing fields
// (Nonce, LeaseKey) are written to 0600 files over stdin only.
type BootstrapInput struct {
	IP           string
	User         string
	Signer       ssh.Signer
	HostKeyPin   string
	Resource     string
	RuntimePort  uint32
	EdgePort     int
	Nonce        string
	APIURL       string
	LeaseKey     []byte
	InstallTools bool
	// InstallNode installs the pinned Node.js and pre-installs AgentPackages
	// (agentruntime.go); Kandev launches its agents with npx on the VM.
	InstallNode   bool
	AgentPackages []string
	// RelayHost/RelayUpstream enable the loopback Git credential broker
	// relay (edge/relay.go): RelayHost is the broker name from Kandev's
	// api_url, RelayUpstream the public origin it is forwarded to.
	RelayHost     string
	RelayUpstream string
	Agentctl      Blob
	Edge          Blob
	// SignCSR issues the leaf for IP from the VM-generated CSR.
	SignCSR func(csrPEM []byte, ip net.IP) (certPEM []byte, notAfter time.Time, err error)
	// Phase reports a finished phase with its duration (no secrets).
	Phase func(name string, d time.Duration)
}

// BootstrapResult is the non-secret outcome.
type BootstrapResult struct {
	HostKey      string
	LeafNotAfter time.Time
}

// Bootstrapper prepares a VM. The SSH implementation is sshBootstrapper;
// unit tests replace it.
type Bootstrapper interface {
	Bootstrap(ctx context.Context, in BootstrapInput) (*BootstrapResult, error)
}

type sshBootstrapper struct{}

func phase(in BootstrapInput, name string, start time.Time) {
	if in.Phase != nil {
		in.Phase(name, time.Since(start))
	}
}

func (sshBootstrapper) Bootstrap(ctx context.Context, in BootstrapInput) (*BootstrapResult, error) {
	t := time.Now()
	conn, _, err := remote.WaitDial(ctx, net.JoinHostPort(in.IP, "22"), in.User, in.Signer, in.HostKeyPin, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	phase(in, "ssh_ready", t)

	// Packages and binaries in parallel: apt is network-bound on the VM side,
	// the uploads are bound by the plugin's uplink.
	var wg sync.WaitGroup
	errs := make([]error, 4)
	if in.InstallNode {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := time.Now()
			if _, err := conn.Run(ctx, agentRuntimeScript(in.AgentPackages), nil); err != nil {
				errs[3] = fmt.Errorf("node agent runtime: %w", err)
			}
			phase(in, "node_agent_runtime", s)
		}()
	}
	if in.InstallTools {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := time.Now()
			// A fresh hostd image runs its own apt job at first boot (seen live:
			// "Could not get lock /var/lib/apt/lists/lock"), and DPkg::Lock::Timeout
			// does not cover the lists lock, so wait for cloud-init and retry.
			// Debian 13's docker.io only Recommends docker-cli, so name it.
			_, errs[0] = conn.Run(ctx, `set -e
if ! command -v docker >/dev/null || ! command -v git >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  command -v cloud-init >/dev/null && timeout 120 cloud-init status --wait >/dev/null 2>&1 || true
  ok=0
  for i in $(seq 1 60); do
    if apt-get -o DPkg::Lock::Timeout=120 -qq update 2>/tmp/apt.err &&
       apt-get -o DPkg::Lock::Timeout=120 -qq install -y --no-install-recommends docker.io docker-cli git ca-certificates curl >/dev/null 2>>/tmp/apt.err; then
      ok=1; break
    fi
    sleep 2
  done
  [ "$ok" = 1 ] || { cat /tmp/apt.err >&2; exit 1; }
fi
systemctl enable --now docker >/dev/null 2>&1 || true
docker info >/dev/null`, nil)
			phase(in, "apt_docker_git", s)
		}()
	}
	for i, b := range []struct {
		blob Blob
		path string
		name string
	}{{in.Agentctl, agentctlPath, "upload_agentctl"}, {in.Edge, edgePath, "upload_edge"}} {
		wg.Add(1)
		go func(i int, blob Blob, path, name string) {
			defer wg.Done()
			s := time.Now()
			errs[i+1] = placeBlob(ctx, conn, blob, path)
			phase(in, name, s)
		}(i, b.blob, b.path, b.name)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return nil, e
		}
	}

	// TLS: key + CSR generated on the VM, leaf signed by the plugin's CA.
	s := time.Now()
	csrPEM, err := conn.Run(ctx, edgePath+" csr --dir "+edgeDir, nil)
	if err != nil {
		return nil, err
	}
	certPEM, notAfter, err := in.SignCSR([]byte(csrPEM), net.ParseIP(in.IP))
	if err != nil {
		return nil, err
	}
	edgeCfg := edge.Config{
		Resource: in.Resource, Listen: fmt.Sprintf(":%d", in.EdgePort), ControlPort: in.RuntimePort,
		InstanceBase: instancePortBase, InstanceMax: instancePortMax,
	}
	if in.RelayHost != "" {
		edgeCfg.Relay = &edge.RelayConfig{Listen: relayListen, Host: in.RelayHost, Upstream: in.RelayUpstream}
		if _, err := conn.Run(ctx, relaySetupScript(in.RelayHost), nil); err != nil {
			return nil, fmt.Errorf("broker relay setup: %w", err)
		}
	}
	cfg, _ := json.Marshal(edgeCfg)
	for _, f := range []struct {
		path string
		mode uint32
		data []byte
	}{
		{edgeDir + "/" + edge.ConfigFile, 0o600, cfg},
		{edgeDir + "/" + edge.LeaseKey, 0o600, in.LeaseKey},
		{edgeDir + "/" + edge.TLSCertFile + ".new", 0o644, certPEM},
	} {
		if err := conn.WriteFile(ctx, f.path, f.mode, bytes.NewReader(f.data), false); err != nil {
			return nil, err
		}
	}
	if _, err := conn.Run(ctx, fmt.Sprintf(`set -e; cd %[1]s
mv -f tls.key.pending tls.key
mv -f tls.crt.new tls.crt`, edgeDir), nil); err != nil {
		return nil, err
	}
	phase(in, "tls_leaf", s)

	// agentctl env file carries the bootstrap nonce (0600, stdin only).
	s = time.Now()
	env := strings.Join([]string{
		"AGENTCTL_BOOTSTRAP_NONCE=" + in.Nonce,
		fmt.Sprintf("AGENTCTL_PORT=%d", in.RuntimePort),
		"AGENTCTL_LISTEN_HOST=127.0.0.1",
		fmt.Sprintf("AGENTCTL_INSTANCE_PORT_BASE=%d", instancePortBase),
		fmt.Sprintf("AGENTCTL_INSTANCE_PORT_MAX=%d", instancePortMax),
		"KANDEV_API_URL=" + in.APIURL,
		"HOME=/root",
	}, "\n") + "\n"
	if err := conn.WriteFile(ctx, "/etc/kandev/agentctl.env.new", 0o600, strings.NewReader(env), false); err != nil {
		return nil, err
	}
	// Restart agentctl only when the nonce changed (a repeated Provision for
	// the same operation and nonce must not kill a handshaken agentctl).
	units := fmt.Sprintf(`set -e
mkdir -p /workspace
cat > /etc/systemd/system/kandev-agentctl.service <<'EOF'
[Unit]
Description=Kandev agentctl (kandev-provider-hostd)
After=network-online.target docker.service
[Service]
EnvironmentFile=/etc/kandev/agentctl.env
ExecStart=%[1]s --workdir /workspace
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/hostd-edge.service <<'EOF'
[Unit]
Description=hostd-edge TLS front (kandev-provider-hostd)
After=network-online.target
[Service]
ExecStart=%[2]s serve --dir %[3]s
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
if ! cmp -s /etc/kandev/agentctl.env.new /etc/kandev/agentctl.env; then
  mv -f /etc/kandev/agentctl.env.new /etc/kandev/agentctl.env
  systemctl enable kandev-agentctl >/dev/null 2>&1
  systemctl restart kandev-agentctl
else
  rm -f /etc/kandev/agentctl.env.new
  systemctl enable --now kandev-agentctl >/dev/null 2>&1
fi
systemctl enable hostd-edge >/dev/null 2>&1
systemctl restart hostd-edge
for i in $(seq 1 50); do
  curl -fsS -o /dev/null http://127.0.0.1:%[4]d/health && exit 0
  sleep 0.2
done
journalctl -u kandev-agentctl -n 20 --no-pager >&2
exit 1`, agentctlPath, edgePath, edgeDir, in.RuntimePort)
	if _, err := conn.Run(ctx, units, nil); err != nil {
		return nil, err
	}
	phase(in, "services_ready", s)
	return &BootstrapResult{HostKey: conn.HostKeySHA, LeafNotAfter: notAfter}, nil
}

func placeBlob(ctx context.Context, conn *remote.Conn, b Blob, path string) error {
	if b.SHA256 != "" {
		if have, err := conn.SHA256Hex(ctx, path); err == nil && have == b.SHA256 {
			return nil
		}
	}
	r, err := b.Open(ctx)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := conn.WriteFile(ctx, path, 0o755, r, true); err != nil {
		return err
	}
	if b.SHA256 != "" {
		have, err := conn.SHA256Hex(ctx, path)
		if err != nil {
			return err
		}
		if have != b.SHA256 {
			return fmt.Errorf("uploaded %s digest mismatch", path)
		}
	}
	return nil
}
