package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostd"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostd/hostdtest"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostdnet"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/lease"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/tlsca"
	"github.com/kdlbs/kandev/pluginsdk"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// testProfileID has the shape of a real Kandev profile ID (uuid.NewString,
// task/service/executor_provider_profiles.go newExecutorProfileID).
const testProfileID = "25806c81-fc5e-496a-907f-de805fc28a43"

type memStore struct {
	mu sync.Mutex
	m  map[string]string
}

// memStore behaves like Kandev's Host secret RPCs, including the key check
// (plugins/host.go checkSecretAccess → codes.InvalidArgument).
func (s *memStore) GetSecret(_ context.Context, k string) (string, bool, error) {
	if !SecretKeyPattern.MatchString(k) {
		return "", false, fmt.Errorf("rpc error: code = InvalidArgument desc = invalid secret key %q", k)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}

func (s *memStore) SetSecret(_ context.Context, k, v string) error {
	if !SecretKeyPattern.MatchString(k) {
		return fmt.Errorf("rpc error: code = InvalidArgument desc = invalid secret key %q", k)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

type fakeBoot struct {
	mu    sync.Mutex
	calls int
	last  BootstrapInput
	leaf  []byte
}

func (b *fakeBoot) Bootstrap(_ context.Context, in BootstrapInput) (*BootstrapResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.last = in
	_, csr, err := tlsca.NewKeyAndCSR()
	if err != nil {
		return nil, err
	}
	leaf, notAfter, err := in.SignCSR(csr, net.ParseIP(in.IP))
	if err != nil {
		return nil, err
	}
	b.leaf = leaf
	return &BootstrapResult{HostKey: "SHA256:test", LeafNotAfter: notAfter}, nil
}

type fixture struct {
	fake  *hostdtest.Server
	store *memStore
	boot  *fakeBoot
	cfg   map[string]string
	sec   map[string]string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	nets, _ := tlsca.ParseCIDRs(hostdnet.Split(hostdnet.DefaultPermittedCIDRs))
	caPEM, caKey, err := tlsca.GenerateCA("test", nets, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(edKey, "")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{fake: hostdtest.New("proj-1"), store: &memStore{}, boot: &fakeBoot{}}
	t.Cleanup(f.fake.Close)
	f.cfg = map[string]string{
		cfgProject: "proj-1", cfgAPIBaseURL: f.fake.URL, cfgSSHKeyID: "32", cfgCACertPEM: string(caPEM), cfgMaxLifetime: "2h",
	}
	f.sec = map[string]string{
		secHostdToken: "test-token", secCAKeyPEM: string(caKey), secSSHKey: string(pem.EncodeToMemory(block)),
		secLeaseSecret: strings.Repeat("s", 40),
	}
	return f
}

func (f *fixture) provider() *Provider {
	p := New()
	p.Secrets = f.store
	p.Bootstrapper = f.boot
	p.Artifact = func(context.Context, *pluginsdk.ExecutorProviderRequestContext, pluginsdk.ExecutorProviderHostAPI) (Blob, error) {
		return Blob{SHA256: strings.Repeat("a", 64)}, nil
	}
	p.EdgeBinary = func() (Blob, error) { return Blob{}, nil }
	p.NewClient = func(b, pr, tok string) HostdAPI {
		c := hostd.New(b, pr, tok)
		c.Sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
		return c
	}
	p.PollEvery, p.IPv4RetryEvery = time.Millisecond, time.Millisecond
	p.Logf, p.Warnf = func(string, ...any) {}, nil
	return p
}

func rc(op string) *pluginsdk.ExecutorProviderRequestContext {
	return &pluginsdk.ExecutorProviderRequestContext{OperationId: op, EnvironmentId: "env-" + op, InputDigest: "d", ExecutionId: op,
		Deadline: time.Now().Add(time.Minute).Format(time.RFC3339Nano)}
}

func (f *fixture) provision(t *testing.T, p *Provider, op string) *pluginsdk.ProvisionExecutorEnvironmentResponse {
	t.Helper()
	resp, err := p.ProvisionExecutorEnvironment(context.Background(), &pluginsdk.ProvisionExecutorEnvironmentRequest{
		Context: rc(op), Profile: &pluginsdk.ExecutorProfileSnapshot{ProfileId: testProfileID, Config: f.cfg, SecretValues: f.sec},
		BootstrapJson: `{"nonce":"n0nce-value","runtime_port":8765,"api_url":"https://kandev.example","execution_id":"` + op + `","artifact_id":"agentctl"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestProvisionIsIdempotentPerOperation(t *testing.T) {
	f := newFixture(t)
	p := f.provider()
	a := f.provision(t, p, "op-A")
	if a.GetError() != nil {
		t.Fatalf("provision error %v", a.GetError())
	}
	b := f.provision(t, p, "op-A")
	if a.GetResource().GetResourceHandle() != b.GetResource().GetResourceHandle() || f.fake.Creates != 1 {
		t.Fatalf("retry must return the same VM: %s vs %s, creates=%d", a.GetResource().GetResourceHandle(), b.GetResource().GetResourceHandle(), f.fake.Creates)
	}
	c := f.provision(t, p, "op-B")
	if c.GetResource().GetResourceHandle() == a.GetResource().GetResourceHandle() || f.fake.Creates != 2 {
		t.Fatal("a different operation must get its own VM")
	}
	// Secrets and the nonce never reach durable state.
	for _, v := range []string{f.sec[secHostdToken], f.sec[secLeaseSecret], "n0nce-value", "PRIVATE KEY"} {
		if strings.Contains(a.GetResource().GetStateJson(), v) {
			t.Fatalf("resource state leaks %q", v)
		}
	}
	if f.boot.last.Nonce != "n0nce-value" || f.boot.last.RuntimePort != 8765 {
		t.Fatal("bootstrap must carry Kandev's nonce and runtime_port")
	}
	// Kandev launches claude-acp with npx on the VM: Node and the pinned
	// agent package are installed by default.
	if !f.boot.last.InstallNode || len(f.boot.last.AgentPackages) != 1 || f.boot.last.AgentPackages[0] != DefaultAgentPackages {
		t.Fatalf("bootstrap must install node and %s by default, got %v %v", DefaultAgentPackages, f.boot.last.InstallNode, f.boot.last.AgentPackages)
	}
}

func TestProvisionRetriesNoFreeIPv4AndLostReply(t *testing.T) {
	f := newFixture(t)
	f.fake.NoFreeIPv4 = 2
	f.fake.DropCreateReply = true
	p := f.provider()
	resp := f.provision(t, p, "op-ip")
	if resp.GetError() != nil || f.fake.Creates != 1 {
		t.Fatalf("got %v creates=%d", resp.GetError(), f.fake.Creates)
	}
}

func TestRecoverFoundAbsent(t *testing.T) {
	f := newFixture(t)
	p := f.provider()
	snap := &pluginsdk.ExecutorProfileSnapshot{ProfileId: testProfileID, Config: f.cfg, SecretValues: f.sec}
	r, _ := p.RecoverExecutorOperation(context.Background(), &pluginsdk.RecoverExecutorOperationRequest{Context: rc("op-R"), Profile: snap})
	if r.GetOutcome() != "absent" {
		t.Fatalf("want absent, got %s", r.GetOutcome())
	}
	prov := f.provision(t, p, "op-R")
	r, _ = p.RecoverExecutorOperation(context.Background(), &pluginsdk.RecoverExecutorOperationRequest{Context: rc("op-R"), Profile: snap})
	if r.GetOutcome() != "found" || r.GetResource().GetResourceHandle() != prov.GetResource().GetResourceHandle() {
		t.Fatalf("want found same handle, got %s %s", r.GetOutcome(), r.GetResource().GetResourceHandle())
	}
	f.fake.RateLimit = 100 // API unavailable within budget → unknown, never absent
	pc := f.provider()
	pc.NewClient = func(b, pr, tok string) HostdAPI {
		c := hostd.New(b, pr, tok)
		c.RetryBudget = 0
		return c
	}
	r, _ = pc.RecoverExecutorOperation(context.Background(), &pluginsdk.RecoverExecutorOperationRequest{Context: rc("op-R"), Profile: snap})
	if r.GetOutcome() != "unknown" {
		t.Fatalf("API failure must be unknown, got %s", r.GetOutcome())
	}
}

func TestResolveLeaseAcceptedByKandevRulesAndEdgeKey(t *testing.T) {
	f := newFixture(t)
	p := f.provider()
	res := f.provision(t, p, "op-L").GetResource()
	// A fresh plugin process (restart) has no profile on Resolve; it must
	// recover credentials from the plugin-owned secret store.
	p2 := f.provider()
	for _, port := range []uint32{8765, 41001} {
		r, err := p2.ResolveExecutorConnection(context.Background(), &pluginsdk.ResolveExecutorConnectionRequest{
			Context: rc("op-L"), Resource: res, Purpose: "agentctl", RuntimePort: port})
		if err != nil || r.GetError() != nil {
			t.Fatalf("port %d: %v %v", port, err, r.GetError())
		}
		l := r.GetLease()
		if err := lease.ValidateForKandev(lease.Lease{BaseURL: l.GetBaseUrl(), HTTPHeaders: l.GetHttpHeaders(), WebSocketHeaders: l.GetWebsocketHeaders(),
			ExpiresAt: l.GetExpiresAt(), Generation: l.GetGeneration()}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(l.GetBaseUrl(), "https://38.56.199.") || !strings.HasSuffix(l.GetBaseUrl(), "/p/"+itoa(port)) {
			t.Fatalf("unexpected base url %s", l.GetBaseUrl())
		}
		if _, err := lease.Verify(f.boot.last.LeaseKey, l.GetHttpHeaders()[lease.Header], res.GetResourceHandle(), port, time.Now()); err != nil {
			t.Fatalf("edge must accept the lease: %v", err)
		}
	}
	r, _ := p2.ResolveExecutorConnection(context.Background(), &pluginsdk.ResolveExecutorConnectionRequest{Context: rc("op-L"), Resource: res, Purpose: "agentctl", RuntimePort: 22})
	if r.GetError() == nil {
		t.Fatal("ports outside agentctl's must be refused")
	}
}

func TestDestroyConfirmedOnlyWhenAbsent(t *testing.T) {
	f := newFixture(t)
	p := f.provider()
	res := f.provision(t, p, "op-D").GetResource()
	f.fake.KeepIPOnDelete = true
	d, _ := p.DestroyExecutorEnvironment(context.Background(), &pluginsdk.DestroyExecutorEnvironmentRequest{Context: rc("op-D"), Resource: res})
	if d.GetConfirmedAbsent() || d.GetError().GetCode() != "public_ip_retained" {
		t.Fatalf("a retained IP must not confirm absence: %v", d)
	}
	f.fake.KeepIPOnDelete = false
	for ip := range f.fake.ReservedIPs {
		delete(f.fake.ReservedIPs, ip)
	}
	p2 := f.provider() // restart: credentials from the store
	d, _ = p2.DestroyExecutorEnvironment(context.Background(), &pluginsdk.DestroyExecutorEnvironmentRequest{Context: rc("op-D"), Resource: res})
	if !d.GetConfirmedAbsent() || f.fake.Count() != 0 {
		t.Fatalf("destroy must confirm: %v count=%d", d, f.fake.Count())
	}
	i, _ := p2.InspectExecutorEnvironment(context.Background(), &pluginsdk.InspectExecutorEnvironmentRequest{Context: rc("op-D"), Resource: res})
	if i.GetState() != "absent" {
		t.Fatalf("inspect after destroy: %s", i.GetState())
	}
	empty := New()
	if d, _ := empty.DestroyExecutorEnvironment(context.Background(), &pluginsdk.DestroyExecutorEnvironmentRequest{Context: rc("op-D"), Resource: res}); d.GetConfirmedAbsent() {
		t.Fatal("without credentials Destroy must never claim absence")
	}
}

func TestValidateProfile(t *testing.T) {
	f := newFixture(t)
	p := f.provider()
	ok, _ := p.ValidateExecutorProfile(context.Background(), &pluginsdk.ValidateExecutorProfileRequest{Profile: &pluginsdk.ExecutorProfileSnapshot{Config: f.cfg, SecretValues: f.sec}})
	if len(ok.GetFieldErrors()) != 0 {
		t.Fatalf("valid profile rejected: %v", ok.GetFieldErrors())
	}
	bad := map[string]string{cfgCPUMode: "turbo", cfgCores: "16", cfgMaxLifetime: "720h", cfgAgentPackages: "x@latest"}
	r, _ := p.ValidateExecutorProfile(context.Background(), &pluginsdk.ValidateExecutorProfileRequest{Profile: &pluginsdk.ExecutorProfileSnapshot{Config: bad}})
	got := map[string]bool{}
	for _, e := range r.GetFieldErrors() {
		got[e.GetField()] = true
	}
	for _, k := range []string{cfgProject, cfgCPUMode, cfgCores, cfgMaxLifetime, cfgCACertPEM, cfgSSHKeyID, cfgAgentPackages} {
		if !got[k] {
			t.Errorf("expected field error for %s", k)
		}
	}
}

// TestManifestMatchesCode keeps manifest.yaml and the Go structs in step.
func TestManifestMatchesCode(t *testing.T) {
	raw, err := os.ReadFile("../../package/manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Capabilities struct {
			ExecutorProvider bool `yaml:"executor_provider"`
			Secrets          bool `yaml:"secrets"`
		} `yaml:"capabilities"`
		Providers []struct {
			Key             string `yaml:"key"`
			ContractVersion int    `yaml:"contract_version"`
			StateVersions   []int  `yaml:"supported_state_versions"`
			ProfileSchema   struct {
				Properties map[string]struct {
					Secret bool `yaml:"secret"`
				} `yaml:"properties"`
			} `yaml:"profile_schema"`
			StateSchema struct {
				Additional *bool                  `yaml:"additionalProperties"`
				Properties map[string]interface{} `yaml:"properties"`
			} `yaml:"resource_state_schema"`
			Capabilities struct {
				MaxLifetime uint64 `yaml:"maximum_lifetime_seconds"`
			} `yaml:"capabilities"`
		} `yaml:"executor_providers"`
	}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if !m.Capabilities.ExecutorProvider || !m.Capabilities.Secrets || len(m.Providers) != 1 {
		t.Fatal("manifest must enable executor_provider and secrets with one provider")
	}
	pv := m.Providers[0]
	if pv.Key != ProviderKey || pv.ContractVersion != 1 || len(pv.StateVersions) != 1 || pv.StateVersions[0] != StateVersion {
		t.Fatal("provider key/contract/state version mismatch")
	}
	if pv.StateSchema.Additional == nil || *pv.StateSchema.Additional {
		t.Fatal("resource_state_schema must set additionalProperties: false")
	}
	if pv.Capabilities.MaxLifetime != uint64(MaxLifetime.Seconds()) {
		t.Fatal("maximum_lifetime_seconds mismatch")
	}
	for _, k := range stateFields() {
		if _, ok := pv.StateSchema.Properties[k]; !ok {
			t.Errorf("state field %s missing from resource_state_schema", k)
		}
	}
	if len(pv.StateSchema.Properties) != len(stateFields()) {
		t.Errorf("resource_state_schema has %d fields, State has %d", len(pv.StateSchema.Properties), len(stateFields()))
	}
	for _, k := range []string{secHostdToken, secCAKeyPEM, secSSHKey, secLeaseSecret} {
		if !pv.ProfileSchema.Properties[k].Secret {
			t.Errorf("%s must be secret: true", k)
		}
	}
	for _, k := range []string{cfgProject, cfgAPIBaseURL, cfgCPUMode, cfgCores, cfgRAMGB, cfgDiskGB, cfgImage, cfgMaxLifetime,
		cfgSSHKeyID, cfgSSHUser, cfgPermittedCIDRs, cfgEdgePort, cfgInstallDocker, cfgInstallNode, cfgAgentPackages, cfgCACertPEM, cfgBrokerUpstream} {
		if _, ok := pv.ProfileSchema.Properties[k]; !ok {
			t.Errorf("profile option %s missing from profile_schema", k)
		}
	}
}

func TestSecretKeyMatchesKandevPattern(t *testing.T) {
	if got := secretKey(testProfileID); got != "profile-credentials."+testProfileID {
		t.Fatalf("a UUID profile ID must be used as is, got %q", got)
	}
	for _, id := range []string{testProfileID, "", "a/b", "../x", "id with spaces", strings.Repeat("x", 200), "prof:1", "ünïcode"} {
		k := secretKey(id)
		if !SecretKeyPattern.MatchString(k) {
			t.Fatalf("secretKey(%q) = %q violates Kandev's plugin secret key pattern", id, k)
		}
	}
	if secretKey("a/b") == secretKey("a/c") {
		t.Fatal("hashed keys must stay distinct per profile")
	}
}

func TestProvisionStoresCredentialsUnderKandevKey(t *testing.T) {
	f := newFixture(t)
	p := f.provider()
	if r := f.provision(t, p, "op-K"); r.GetError() != nil {
		t.Fatalf("provision error %v", r.GetError())
	}
	if _, ok := f.store.m["profile-credentials."+testProfileID]; !ok || len(f.store.m) != 1 {
		t.Fatalf("credentials must be stored under the Kandev-valid key, store has %d keys", len(f.store.m))
	}
}

// failStore rejects every key, like Kandev's Host did for the v0.1.0 key.
type failStore struct{}

func (failStore) GetSecret(context.Context, string) (string, bool, error) {
	return "", false, fmt.Errorf("rpc error: code = InvalidArgument desc = invalid secret key")
}
func (failStore) SetSecret(context.Context, string, string) error {
	return fmt.Errorf("rpc error: code = InvalidArgument desc = invalid secret key")
}

func TestCredentialFailuresAreLoggedWithoutSecrets(t *testing.T) {
	f := newFixture(t)
	p := f.provider()
	p.Secrets = failStore{}
	var mu sync.Mutex
	var logs []string
	p.Logf = func(format string, a ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, a...))
		mu.Unlock()
	}
	p.Warnf = p.Logf
	if r := f.provision(t, p, "op-F"); r.GetError().GetCode() != "invalid_credentials" || r.GetResource() != nil {
		t.Fatalf("want invalid_credentials without a resource, got %v", r.GetError())
	}
	snap := &pluginsdk.ExecutorProfileSnapshot{ProfileId: testProfileID, Config: f.cfg, SecretValues: f.sec}
	if r, _ := p.RecoverExecutorOperation(context.Background(), &pluginsdk.RecoverExecutorOperationRequest{Context: rc("op-F"), Profile: snap}); r.GetOutcome() != "unknown" {
		t.Fatalf("want unknown, got %s", r.GetOutcome())
	}
	if f.fake.Creates != 0 {
		t.Fatal("no VM may be created without stored credentials")
	}
	if len(logs) != 2 || !strings.Contains(logs[0], "invalid secret key") || !strings.Contains(logs[1], "recover credentials") {
		t.Fatalf("both credential paths must log the cause, got %q", logs)
	}
	for _, l := range logs {
		for _, v := range []string{f.sec[secHostdToken], f.sec[secLeaseSecret], "PRIVATE KEY"} {
			if strings.Contains(l, v) {
				t.Fatalf("log leaks a secret: %q", l)
			}
		}
	}
}
