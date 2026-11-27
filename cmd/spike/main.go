// Command spike is the live harness: it drives the provider exactly the way
// Kandev's PluginRemoteExecutor does (Provision → ResolveExecutorConnection →
// HTTPS to the lease URL → Destroy) against the real hostd API, without a
// Kandev host. It creates real, billed VMs.
//
//	HOSTD_API_TOKEN=... go run ./cmd/spike -project <uuid> -ssh-key-id 32 \
//	    -ssh-key ./key -agentctl ./agentctl-linux-amd64 -edge ./hostd-edge-linux-amd64
//
// The token is read from the environment and never printed.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostd"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostdnet"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/lease"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/provider"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/tlsca"
	"github.com/kdlbs/kandev/pluginsdk"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

// memStore enforces Kandev's plugin secret key pattern like the real Host.
func (s *memStore) GetSecret(_ context.Context, k string) (string, bool, error) {
	if !provider.SecretKeyPattern.MatchString(k) {
		return "", false, fmt.Errorf("invalid secret key %q", k)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}
func (s *memStore) SetSecret(_ context.Context, k, v string) error {
	if !provider.SecretKeyPattern.MatchString(k) {
		return fmt.Errorf("invalid secret key %q", k)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

// callbacks records Kandev host callbacks (progress/checkpoints).
type callbacks struct{ t0 time.Time }

func (c *callbacks) CheckpointExecutorResource(_ context.Context, r *pluginsdk.CheckpointExecutorResourceRequest) (*pluginsdk.CheckpointExecutorResourceResponse, error) {
	logf("callback checkpoint phase=%s handle=%s", r.GetPhase(), r.GetResource().GetResourceHandle())
	return &pluginsdk.CheckpointExecutorResourceResponse{Accepted: true}, nil
}
func (c *callbacks) ReportExecutorProgress(_ context.Context, r *pluginsdk.ReportExecutorProgressRequest) (*pluginsdk.ReportExecutorProgressResponse, error) {
	logf("callback progress %s %d/%d", r.GetStage(), r.GetCompleted(), r.GetTotal())
	return &pluginsdk.ReportExecutorProgressResponse{Accepted: true}, nil
}
func (c *callbacks) ReadExecutorRuntimeArtifact(context.Context, *pluginsdk.ReadExecutorRuntimeArtifactRequest, func(*pluginsdk.ExecutorRuntimeArtifactChunk) error) error {
	return fmt.Errorf("not used by the harness")
}

var start = time.Now()

func logf(format string, args ...any) {
	fmt.Printf("[%7.2fs] %s\n", time.Since(start).Seconds(), fmt.Sprintf(format, args...))
}

type timing struct {
	Phase   string  `json:"phase"`
	Seconds float64 `json:"seconds"`
}

func main() {
	project := flag.String("project", "", "hostd project UUID")
	keyID := flag.Int64("ssh-key-id", 0, "hostd SSH key id")
	keyPath := flag.String("ssh-key", "", "SSH private key file for that key id")
	agentctl := flag.String("agentctl", "", "agentctl linux-amd64 binary")
	edgeBin := flag.String("edge", "", "hostd-edge linux-amd64 binary")
	cidrs := flag.String("cidrs", hostdnet.DefaultPermittedCIDRs, "CA permitted IPv4 ranges")
	op := flag.String("op", "", "operation id (default random)")
	out := flag.String("out", "", "write timings JSON here")
	keep := flag.Bool("keep", false, "do not destroy (never use in CI)")
	flag.Parse()
	token := os.Getenv("HOSTD_API_TOKEN")
	if *project == "" || *keyID == 0 || *keyPath == "" || *agentctl == "" || *edgeBin == "" || token == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *op == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		*op = "spike-" + hex.EncodeToString(b)
	}
	var timings []timing
	mark := func(name string, t time.Time) {
		d := time.Since(t).Seconds()
		timings = append(timings, timing{name, d})
		logf("TIMING %-28s %7.2fs", name, d)
	}
	fail := func(format string, args ...any) {
		logf("FAIL "+format, args...)
		os.Exit(1)
	}

	// Ephemeral spike CA (production: an offline CA whose key is a profile secret).
	nets, err := tlsca.ParseCIDRs(strings.Split(*cidrs, ","))
	if err != nil {
		fail("%v", err)
	}
	caPEM, caKeyPEM, err := tlsca.GenerateCA("kandev-provider-hostd spike CA", nets, 48*time.Hour)
	if err != nil {
		fail("%v", err)
	}
	ca, _ := tlsca.Load(caPEM, caKeyPEM)
	sshKey, err := os.ReadFile(*keyPath)
	if err != nil {
		fail("read ssh key: %v", err)
	}
	leaseSecret := make([]byte, 32)
	_, _ = rand.Read(leaseSecret)

	p := provider.New()
	p.Secrets = &memStore{}
	p.Callbacks = &callbacks{}
	p.Logf = func(f string, a ...any) { logf("provider: "+f, a...) }
	p.Artifact = func(context.Context, *pluginsdk.ExecutorProviderRequestContext, pluginsdk.ExecutorProviderHostAPI) (provider.Blob, error) {
		return provider.FileBlob(*agentctl)
	}
	p.EdgeBinary = func() (provider.Blob, error) { return provider.FileBlob(*edgeBin) }

	profile := &pluginsdk.ExecutorProfileSnapshot{
		ProfileId: "spike-profile",
		Config: map[string]string{
			"project": *project, "cpu_mode": "light", "cores": "2", "ram_gb": "4", "disk_gb": "20",
			"image": "debian-13-amd64.qcow2", "max_lifetime": "2h", "ssh_key_id": fmt.Sprint(*keyID),
			"ssh_user": "kandev", "permitted_cidrs": *cidrs, "edge_port": "8443", "ca_cert_pem": string(caPEM),
		},
		SecretValues: map[string]string{
			"hostd_api_token": token, "ca_key_pem": string(caKeyPEM), "ssh_private_key": string(sshKey),
			"lease_secret": hex.EncodeToString(leaseSecret),
		},
	}
	nonceBytes := make([]byte, 32)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)
	boot, _ := json.Marshal(map[string]any{"nonce": nonce, "runtime_port": 8765, "api_url": "https://kandev.invalid",
		"execution_id": *op, "artifact_id": "agentctl"})
	rctx := func(d time.Duration) *pluginsdk.ExecutorProviderRequestContext {
		return &pluginsdk.ExecutorProviderRequestContext{PluginId: "kandev-provider-hostd", ProviderKey: provider.ProviderKey, ContractVersion: 1,
			OperationId: *op, EnvironmentId: "env-" + *op, ExecutionId: *op, InputDigest: "spike-digest", DispatchGeneration: 1,
			Deadline: time.Now().Add(d).UTC().Format(time.RFC3339Nano)}
	}
	ctx := context.Background()
	hc := hostd.New("", *project, token)
	logf("operation %s → hostname %s", *op, provider.Hostname(*op))

	var resource *pluginsdk.ExecutorResourceDescriptor
	cleanup := func() {
		if *keep {
			logf("KEEP set: VM left running")
			return
		}
		ids, err := hc.VMIDsByName(ctx, provider.Hostname(*op))
		if err != nil {
			logf("cleanup list failed: %v", err)
			return
		}
		for _, id := range ids {
			ok, err := hc.DestroyVM(ctx, id, provider.Hostname(*op), 2*time.Second)
			logf("cleanup vm %d absent=%v err=%v", id, ok, err)
		}
	}
	defer cleanup()
	defer func() {
		if r := recover(); r != nil {
			cleanup()
			panic(r)
		}
	}()

	// 1. Provision (Kandev caps the launch at 10 min).
	t := time.Now()
	pr, err := p.ProvisionExecutorEnvironment(ctx, &pluginsdk.ProvisionExecutorEnvironmentRequest{Context: rctx(10 * time.Minute), Profile: profile, BootstrapJson: string(boot)})
	if err != nil {
		cleanup()
		fail("provision: %v", err)
	}
	if pr.GetError() != nil {
		cleanup()
		fail("provision provider error: %s", pr.GetError().GetCode())
	}
	mark("provision_total", t)
	resource = pr.GetResource()
	logf("resource %s state=%s expires=%s", resource.GetResourceHandle(), resource.GetStateJson(), resource.GetExpiresAt())
	for _, secret := range []string{token, string(caKeyPEM), nonce, hex.EncodeToString(leaseSecret)} {
		if strings.Contains(resource.GetStateJson(), secret) {
			cleanup()
			fail("resource state leaks a secret")
		}
	}

	// 2. ResolveExecutorConnection for the control port.
	t = time.Now()
	rr, err := p.ResolveExecutorConnection(ctx, &pluginsdk.ResolveExecutorConnectionRequest{Context: rctx(15 * time.Second), Resource: resource, Purpose: "agentctl", RuntimePort: 8765})
	if err != nil || rr.GetError() != nil {
		cleanup()
		fail("resolve: %v %v", err, rr.GetError())
	}
	mark("resolve_lease", t)
	l := rr.GetLease()
	logf("lease base_url=%s expires=%s generation=%s headers=%d", l.GetBaseUrl(), l.GetExpiresAt(), l.GetGeneration(), len(l.GetHttpHeaders()))

	// 3. HTTPS to the lease URL, trusting ONLY the spike CA (as Kandev would via SSL_CERT_FILE).
	caOnly := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12}}}
	get := func(c *http.Client, method, url string, hdr map[string]string, body []byte) (int, string, *tls.ConnectionState, error) {
		req, _ := http.NewRequest(method, url, bytes.NewReader(body))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0, "", nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, string(b), resp.TLS, nil
	}
	t = time.Now()
	code, body, state, err := get(caOnly, http.MethodGet, l.GetBaseUrl()+"/health", l.GetHttpHeaders(), nil)
	if err != nil || code != 200 {
		cleanup()
		fail("GET /health via lease: code=%d err=%v body=%q", code, err, body)
	}
	mark("https_health_first", t)
	leaf := state.PeerCertificates[0]
	logf("TLS ok: version=%x leaf CN=%s IPs=%v notAfter=%s issuer=%q; agentctl /health → %d %s",
		state.Version, leaf.Subject.CommonName, leaf.IPAddresses, leaf.NotAfter.Format(time.RFC3339), leaf.Issuer.CommonName, code, strings.TrimSpace(body))

	// 4. Bootstrap nonce semantics: the nonce Kandev put in bootstrap_json buys
	// exactly one agentctl token over the leased endpoint.
	hs, _ := json.Marshal(map[string]string{"nonce": nonce})
	t = time.Now()
	code, body, _, err = get(caOnly, http.MethodPost, l.GetBaseUrl()+"/auth/handshake", l.GetHttpHeaders(), hs)
	mark("handshake", t)
	if err != nil || code != 200 || !strings.Contains(body, `"token"`) {
		cleanup()
		fail("handshake: code=%d err=%v", code, err)
	}
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal([]byte(body), &tok)
	logf("handshake → 200, agentctl token length %d (not printed)", len(tok.Token))
	code, _, _, _ = get(caOnly, http.MethodPost, l.GetBaseUrl()+"/auth/handshake", l.GetHttpHeaders(), hs)
	logf("second handshake with the same nonce → %d (want non-200: nonce burned)", code)
	if code == 200 {
		cleanup()
		fail("nonce was not burned")
	}

	// 5. Negative checks.
	code, _, _, err = get(caOnly, http.MethodGet, l.GetBaseUrl()+"/health", nil, nil)
	logf("no lease header → %d err=%v (want 401)", code, err)
	if code != 401 {
		cleanup()
		fail("edge accepted a request without a lease")
	}
	other, _ := lease.Mint(lease.DeriveVMKey([]byte("wrong-secret-wrong-secret-wrong!"), *op), lease.Claims{Resource: resource.GetResourceHandle(), Port: 8765, Generation: "x", Expires: time.Now().Add(time.Minute).Unix()})
	code, _, _, _ = get(caOnly, http.MethodGet, l.GetBaseUrl()+"/health", map[string]string{lease.Header: other}, nil)
	logf("forged lease → %d (want 401)", code)
	if code != 401 {
		cleanup()
		fail("edge accepted a forged lease")
	}
	_, _, _, err = get(&http.Client{Timeout: 10 * time.Second}, http.MethodGet, l.GetBaseUrl()+"/health", l.GetHttpHeaders(), nil)
	logf("system roots only → err=%v (want x509 unknown authority)", err)
	if err == nil {
		cleanup()
		fail("system roots trusted the private CA")
	}
	ir, _ := p.ResolveExecutorConnection(ctx, &pluginsdk.ResolveExecutorConnectionRequest{Context: rctx(15 * time.Second), Resource: resource, Purpose: "agentctl", RuntimePort: 41001})
	code, _, _, err = get(caOnly, http.MethodGet, ir.GetLease().GetBaseUrl()+"/health", ir.GetLease().GetHttpHeaders(), nil)
	logf("instance-port lease (41001, no instance yet) → %d err=%v (want 502 from the edge: routed, upstream absent)", code, err)
	code, _, _, _ = get(caOnly, http.MethodGet, ir.GetLease().GetBaseUrl()+"/health", l.GetHttpHeaders(), nil)
	logf("control-port lease used on instance port → %d (want 401: lease bound to its port)", code)

	// 6. Idempotency against the live API: same operation → same VM, agentctl untouched.
	t = time.Now()
	pr2, err := p.ProvisionExecutorEnvironment(ctx, &pluginsdk.ProvisionExecutorEnvironmentRequest{Context: rctx(10 * time.Minute), Profile: profile, BootstrapJson: string(boot)})
	mark("provision_retry_same_op", t)
	if err != nil || pr2.GetError() != nil || pr2.GetResource().GetResourceHandle() != resource.GetResourceHandle() {
		cleanup()
		fail("retry did not adopt: %v %v %s", err, pr2.GetError(), pr2.GetResource().GetResourceHandle())
	}
	logf("retry adopted %s", pr2.GetResource().GetResourceHandle())
	code, _, _, _ = get(caOnly, http.MethodPost, l.GetBaseUrl()+"/auth/handshake", l.GetHttpHeaders(), hs)
	logf("handshake after retry → %d (want non-200: agentctl not restarted, nonce stays burned)", code)
	rec, _ := p.RecoverExecutorOperation(ctx, &pluginsdk.RecoverExecutorOperationRequest{Context: rctx(time.Minute), Profile: profile})
	logf("recover → %s %s", rec.GetOutcome(), rec.GetResource().GetResourceHandle())
	ins, _ := p.InspectExecutorEnvironment(ctx, &pluginsdk.InspectExecutorEnvironmentRequest{Context: rctx(time.Minute), Resource: resource})
	logf("inspect → %s expires=%s", ins.GetState(), ins.GetExpiresAt())
	att, _ := p.AttachExecutorEnvironment(ctx, &pluginsdk.AttachExecutorEnvironmentRequest{Context: rctx(time.Minute), Resource: resource})
	logf("attach → handle=%s err=%v", att.GetResource().GetResourceHandle(), att.GetError())

	if *keep {
		return
	}
	// 7. Destroy (Kandev gives launch-failure cleanup 30 s; task cleanup retries).
	t = time.Now()
	attempts := 0
	for {
		attempts++
		dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		dr, err := p.DestroyExecutorEnvironment(dctx, &pluginsdk.DestroyExecutorEnvironmentRequest{Context: rctx(30 * time.Second), Resource: resource, CleanupReason: "task_cleanup"})
		cancel()
		if err == nil && dr.GetConfirmedAbsent() {
			break
		}
		logf("destroy attempt %d: confirmed=%v err=%v providerErr=%v", attempts, dr.GetConfirmedAbsent(), err, dr.GetError())
		if attempts >= 6 {
			fail("destroy not confirmed")
		}
		time.Sleep(5 * time.Second)
	}
	mark(fmt.Sprintf("destroy_confirmed(%d calls)", attempts), t)
	ins, _ = p.InspectExecutorEnvironment(ctx, &pluginsdk.InspectExecutorEnvironmentRequest{Context: rctx(time.Minute), Resource: resource})
	rec, _ = p.RecoverExecutorOperation(ctx, &pluginsdk.RecoverExecutorOperationRequest{Context: rctx(time.Minute), Profile: profile})
	logf("after destroy: inspect → %s, recover → %s", ins.GetState(), rec.GetOutcome())
	vms, err1 := hc.ListVMs(ctx)
	ips, err2 := hc.ListPublicIPs(ctx)
	logf("project now: %d VMs (err %v), %d public IPs (err %v)", len(vms), err1, len(ips), err2)
	if *out != "" {
		b, _ := json.MarshalIndent(map[string]any{"operation": *op, "timings": timings, "vms_left": len(vms), "ips_left": len(ips)}, "", " ")
		_ = os.WriteFile(*out, b, 0o600)
	}
	logf("PASS")
}
