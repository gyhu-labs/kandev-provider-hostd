// Package provider implements pluginsdk.ExecutorProviderPlugin on hostd.cloud
// VMs: one VM per Kandev environment, agentctl behind a per-VM TLS front whose
// IP certificate is issued by the plugin's name-constrained CA.
package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostd"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/lease"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/tlsca"
	"github.com/kdlbs/kandev/pluginsdk"
)

// ProviderKey is the manifest's executor_providers[].key.
const ProviderKey = "hostd-vm"

// LeaseLifetime of one connection lease. Kandev refreshes 30 s before expiry.
const LeaseLifetime = 10 * time.Minute

// SecretStore is the subset of pluginsdk.Host used to keep profile secrets
// for the RPCs that receive no profile (Attach, Inspect, Resolve, Destroy).
type SecretStore interface {
	GetSecret(ctx context.Context, key string) (string, bool, error)
	SetSecret(ctx context.Context, key, value string) error
}

// HostdAPI is the hostd client surface the provider uses.
type HostdAPI interface {
	EnsureVM(ctx context.Context, in hostd.CreateVMInput, ipv4RetryEvery time.Duration) (int64, hostd.CreateOutcome, int, error)
	VMIDsByName(ctx context.Context, hostname string) ([]int64, error)
	GetVM(ctx context.Context, vmid int64) (*hostd.VM, error)
	GetVMConfig(ctx context.Context, vmid int64) (*hostd.VMConfig, error)
	DestroyVM(ctx context.Context, vmid int64, poll time.Duration) (bool, error)
	ListPublicIPs(ctx context.Context) ([]hostd.PublicIP, error)
}

// Provider is the plugin. Zero external state: hostd is the inventory.
type Provider struct {
	pluginsdk.UnimplementedPlugin

	// Overrides for the local harness and tests; production uses Host().
	Callbacks    pluginsdk.ExecutorProviderHostAPI
	Secrets      SecretStore
	Artifact     func(ctx context.Context, rc *pluginsdk.ExecutorProviderRequestContext, callbacks pluginsdk.ExecutorProviderHostAPI) (Blob, error)
	EdgeBinary   func() (Blob, error)
	NewClient    func(baseURL, project, token string) HostdAPI
	Bootstrapper Bootstrapper
	Now          func() time.Time
	Logf         func(format string, args ...any)
	// PollEvery and IPv4RetryEvery tune waits (tests set them to ~0).
	PollEvery      time.Duration
	IPv4RetryEvery time.Duration

	mu      sync.Mutex
	opLocks map[string]*sync.Mutex
	creds   map[string]*Credentials
	memSec  map[string]string
}

var _ pluginsdk.ExecutorProviderPlugin = (*Provider)(nil)

// New returns a provider with production defaults.
func New() *Provider {
	return &Provider{
		Artifact:     hostArtifact,
		EdgeBinary:   defaultEdgeBinary,
		NewClient:    func(b, p, t string) HostdAPI { return hostd.New(b, p, t) },
		Bootstrapper: sshBootstrapper{},
		Now:          time.Now,
		Logf:         log.Printf,
		PollEvery:    2 * time.Second, IPv4RetryEvery: 15 * time.Second,
	}
}

func (p *Provider) lockOp(op string) func() {
	p.mu.Lock()
	if p.opLocks == nil {
		p.opLocks = map[string]*sync.Mutex{}
	}
	l := p.opLocks[op]
	if l == nil {
		l = &sync.Mutex{}
		p.opLocks[op] = l
	}
	p.mu.Unlock()
	l.Lock()
	return l.Unlock
}

func (p *Provider) callbacks() pluginsdk.ExecutorProviderHostAPI {
	if p.Callbacks != nil {
		return p.Callbacks
	}
	if h, ok := p.Host().(pluginsdk.ExecutorProviderHost); ok {
		return h.ExecutorProvider()
	}
	return nil
}

func (p *Provider) secretStore() SecretStore {
	if p.Secrets != nil {
		return p.Secrets
	}
	if h := p.Host(); h != nil {
		return h
	}
	return nil
}

func secretKey(profileID string) string { return "profile-credentials/" + profileID }

// rememberCredentials parses the profile's transient secrets and keeps them
// in the plugin-owned secret store (Kandev's encrypted vault) keyed by
// profile ID, because Attach/Inspect/Resolve/Destroy carry no profile.
func (p *Provider) rememberCredentials(ctx context.Context, prof *Profile, values map[string]string) (*Credentials, error) {
	s := secretsFrom(values)
	if !s.complete() {
		// Secret fields kept unchanged in the profile editor may arrive empty;
		// fall back to what an earlier operation stored.
		return p.loadCredentials(ctx, prof.ID)
	}
	creds, err := ParseCredentials(prof, s)
	if err != nil {
		return nil, err
	}
	if store := p.secretStore(); store != nil {
		s.CACertPEM = prof.CACertPEM // public, stored alongside so profile-less RPCs can rebuild the CA
		if err := store.SetSecret(ctx, secretKey(prof.ID), s.marshal()); err != nil {
			return nil, fmt.Errorf("store profile credentials: %w", err)
		}
	}
	p.cacheCredentials(prof.ID, creds)
	return creds, nil
}

func (p *Provider) cacheCredentials(profileID string, c *Credentials) {
	p.mu.Lock()
	if p.creds == nil {
		p.creds = map[string]*Credentials{}
	}
	p.creds[profileID] = c
	p.mu.Unlock()
}

// loadCredentials serves the RPCs that carry no profile (Attach, Inspect,
// Resolve, Destroy): memory first, then the plugin-owned secret store, which
// survives a plugin restart or upgrade.
func (p *Provider) loadCredentials(ctx context.Context, profileID string) (*Credentials, error) {
	p.mu.Lock()
	c := p.creds[profileID]
	p.mu.Unlock()
	if c != nil {
		return c, nil
	}
	store := p.secretStore()
	if store == nil || profileID == "" {
		return nil, errors.New("profile credentials are unavailable")
	}
	raw, found, err := store.GetSecret(ctx, secretKey(profileID))
	if err != nil || !found {
		return nil, errors.New("profile credentials are unavailable")
	}
	var s Secrets
	if err := json.Unmarshal([]byte(raw), &s); err != nil || s.CACertPEM == "" {
		return nil, errors.New("stored profile credentials are invalid")
	}
	cert, err := tlsca.ParseCertificatePEM([]byte(s.CACertPEM))
	if err != nil {
		return nil, errors.New("stored CA certificate is invalid")
	}
	c, err = ParseCredentials(&Profile{CACertPEM: s.CACertPEM, PermittedCIDRs: cert.PermittedIPRanges}, s)
	if err != nil {
		return nil, err
	}
	p.cacheCredentials(profileID, c)
	return c, nil
}

func (p *Provider) credsForState(ctx context.Context, s State) (*Credentials, error) {
	return p.loadCredentials(ctx, s.ProfileID)
}

func providerError(code string, retryAfter uint32, fields ...*pluginsdk.ExecutorProviderFieldError) *pluginsdk.ExecutorProviderError {
	return &pluginsdk.ExecutorProviderError{Code: code, MessageId: "provider.hostd." + code, Fields: fields, RetryAfterSeconds: retryAfter}
}

func validateContext(rc *pluginsdk.ExecutorProviderRequestContext) error {
	if rc == nil || rc.GetOperationId() == "" || rc.GetEnvironmentId() == "" || rc.GetInputDigest() == "" {
		return errors.New("hostd provider: operation identity is incomplete")
	}
	return nil
}

func withRequestDeadline(ctx context.Context, rc *pluginsdk.ExecutorProviderRequestContext) (context.Context, context.CancelFunc) {
	if d, err := time.Parse(time.RFC3339Nano, rc.GetDeadline()); err == nil {
		if cur, ok := ctx.Deadline(); !ok || d.Before(cur) {
			return context.WithDeadline(ctx, d)
		}
	}
	return context.WithCancel(ctx)
}

// ValidateExecutorProfile checks the non-secret profile and, when present,
// the secrets. It makes no network calls.
func (p *Provider) ValidateExecutorProfile(_ context.Context, req *pluginsdk.ValidateExecutorProfileRequest) (*pluginsdk.ValidateExecutorProfileResponse, error) {
	prof, ferrs := ParseProfile(req.GetProfile())
	if len(ferrs) == 0 {
		s := secretsFrom(req.GetProfile().GetSecretValues())
		if s.HostdToken != "" || s.CAKeyPEM != "" || s.SSHKey != "" || s.LeaseSecret != "" {
			if _, err := ParseCredentials(prof, s); err != nil {
				ferrs = append(ferrs, fieldErr(secCAKeyPEM, "invalid_credentials"))
			}
		}
	}
	return &pluginsdk.ValidateExecutorProfileResponse{FieldErrors: ferrs, Capabilities: capabilities()}, nil
}

// ProvisionExecutorEnvironment creates (or adopts) the operation's VM and
// bootstraps agentctl behind the TLS edge.
func (p *Provider) ProvisionExecutorEnvironment(ctx context.Context, req *pluginsdk.ProvisionExecutorEnvironmentRequest) (*pluginsdk.ProvisionExecutorEnvironmentResponse, error) {
	rc := req.GetContext()
	if err := validateContext(rc); err != nil {
		return nil, err
	}
	prof, ferrs := ParseProfile(req.GetProfile())
	if len(ferrs) > 0 {
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Error: providerError("invalid_profile", 0, ferrs...)}, nil
	}
	creds, err := p.rememberCredentials(ctx, prof, req.GetProfile().GetSecretValues())
	if err != nil {
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Error: providerError("invalid_credentials", 0)}, nil
	}
	boot, err := parseBootstrap(req.GetBootstrapJson())
	if err != nil {
		return nil, err
	}
	unlock := p.lockOp(rc.GetOperationId())
	defer unlock()
	ctx, cancel := withRequestDeadline(ctx, rc)
	defer cancel()

	client := p.NewClient(prof.APIBaseURL, prof.Project, creds.Token)
	hostname := Hostname(rc.GetOperationId())
	cb := p.callbacks()
	p.progress(ctx, cb, rc, "provision", 0, 4)
	t := p.Now()
	vmid, outcome, ipRetries, err := client.EnsureVM(ctx, hostd.CreateVMInput{
		Hostname: hostname, Username: prof.SSHUser, Password: randomPassword(), SSHKeyIDs: []int64{prof.SSHKeyID},
		Cores: prof.Cores, RAMGB: prof.RAMGB, OSDiskGB: prof.DiskGB, OSImage: prof.Image, CPUMode: prof.CPUMode, WANMode: "ipv4",
	}, p.IPv4RetryEvery)
	switch {
	case hostd.IsQuota(err):
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Error: providerError("quota_exceeded", 0)}, nil
	case hostd.IsNoFreeIPv4(err):
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Error: providerError("capacity_unavailable", 60)}, nil
	case err != nil:
		// Unknown outcome: Kandev calls RecoverExecutorOperation next.
		return nil, fmt.Errorf("hostd provider: create VM: %w", err)
	}
	p.logf("op=%s vm=%d %s in %s (ipv4 retries %d)", short(rc.GetOperationId()), vmid, outcome, p.Now().Sub(t).Round(time.Millisecond), ipRetries)

	ip, err := p.waitIPv4(ctx, client, vmid)
	if err != nil {
		return nil, err
	}
	now := p.Now().UTC()
	state := State{
		VMID: vmid, IP: ip, Project: prof.Project, Hostname: hostname, ProfileID: prof.ID, APIBaseURL: prof.APIBaseURL,
		SSHUser: prof.SSHUser, EdgePort: prof.EdgePort, CPUMode: prof.CPUMode, Cores: prof.Cores, RAMGB: prof.RAMGB,
		CreatedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(prof.MaxLifetime).Format(time.RFC3339Nano),
	}
	if !creds.CA.Permits(net.ParseIP(ip)) {
		// The CA cannot certify this address, so Kandev could never verify the
		// edge: fail before spending time on the bootstrap.
		p.logf("op=%s vm=%d ip %s is outside the CA constraints", short(rc.GetOperationId()), vmid, ip)
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Resource: descriptor(state), Error: providerError("ip_outside_ca_constraints", 0)}, nil
	}
	p.checkpoint(ctx, cb, rc, state, "bootstrapping")
	p.progress(ctx, cb, rc, "provision", 1, 4)

	agentctl, err := p.Artifact(ctx, rc, cb)
	if err != nil {
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Resource: descriptor(state), Error: providerError("artifact_unavailable", 0)}, nil
	}
	edgeBin, err := p.EdgeBinary()
	if err != nil {
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Resource: descriptor(state), Error: providerError("edge_unavailable", 0)}, nil
	}
	p.progress(ctx, cb, rc, "artifact", 2, 4)
	res, err := p.Bootstrapper.Bootstrap(ctx, BootstrapInput{
		IP: ip, User: prof.SSHUser, Signer: creds.SSHSigner, Resource: Handle(prof.Project, vmid),
		RuntimePort: boot.RuntimePort, EdgePort: prof.EdgePort, Nonce: boot.Nonce, APIURL: boot.APIURL,
		LeaseKey: lease.DeriveVMKey(creds.LeaseSecret, rc.GetOperationId()), InstallTools: prof.InstallDocker,
		Agentctl: agentctl, Edge: edgeBin,
		SignCSR: func(csr []byte, leafIP net.IP) ([]byte, time.Time, error) {
			certPEM, cert, err := creds.CA.IssueLeaf(csr, leafIP, prof.MaxLifetime)
			if err != nil {
				return nil, time.Time{}, err
			}
			return certPEM, cert.NotAfter, nil
		},
		Phase: func(name string, d time.Duration) {
			p.logf("op=%s vm=%d phase %s %s", short(rc.GetOperationId()), vmid, name, d.Round(time.Millisecond))
		},
	})
	if err != nil {
		p.logf("op=%s vm=%d bootstrap failed: %v", short(rc.GetOperationId()), vmid, err)
		// Return the resource with the error so Kandev destroys it.
		return &pluginsdk.ProvisionExecutorEnvironmentResponse{Resource: descriptor(state), Error: providerError("bootstrap_failed", 0)}, nil
	}
	state.SSHHostKey = res.HostKey
	state.LeafExpiresAt = res.LeafNotAfter.UTC().Format(time.RFC3339Nano)
	state.Bootstrapped = true
	p.progress(ctx, cb, rc, "readiness", 4, 4)
	return &pluginsdk.ProvisionExecutorEnvironmentResponse{Resource: descriptor(state)}, nil
}

func (p *Provider) waitIPv4(ctx context.Context, c HostdAPI, vmid int64) (string, error) {
	for {
		cfg, err := c.GetVMConfig(ctx, vmid)
		if err != nil {
			return "", err
		}
		if ip := cfg.IPv4(); ip != "" {
			parsed := net.ParseIP(ip)
			if parsed == nil || lease.ProhibitedAddress(parsed) != nil {
				return "", fmt.Errorf("hostd provider: VM %d has an unusable IPv4", vmid)
			}
			return ip, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(p.PollEvery):
		}
	}
}

// RecoverExecutorOperation answers found/absent/unknown for an operation
// whose Provision reply was lost, by looking the VM up by its derived name.
func (p *Provider) RecoverExecutorOperation(ctx context.Context, req *pluginsdk.RecoverExecutorOperationRequest) (*pluginsdk.RecoverExecutorOperationResponse, error) {
	rc := req.GetContext()
	if err := validateContext(rc); err != nil {
		return nil, err
	}
	prof, ferrs := ParseProfile(req.GetProfile())
	if len(ferrs) > 0 {
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "unknown", Error: providerError("invalid_profile", 0, ferrs...)}, nil
	}
	creds, err := p.rememberCredentials(ctx, prof, req.GetProfile().GetSecretValues())
	if err != nil {
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "unknown", Error: providerError("credentials_unavailable", 0)}, nil
	}
	client := p.NewClient(prof.APIBaseURL, prof.Project, creds.Token)
	hostname := Hostname(rc.GetOperationId())
	ids, err := client.VMIDsByName(ctx, hostname)
	if err != nil || len(ids) > 1 {
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "unknown"}, nil
	}
	if len(ids) == 0 {
		return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "absent"}, nil
	}
	state := State{VMID: ids[0], Project: prof.Project, Hostname: hostname, ProfileID: prof.ID, APIBaseURL: prof.APIBaseURL,
		SSHUser: prof.SSHUser, EdgePort: prof.EdgePort, CPUMode: prof.CPUMode, Cores: prof.Cores, RAMGB: prof.RAMGB,
		CreatedAt: p.Now().UTC().Format(time.RFC3339Nano), ExpiresAt: p.Now().UTC().Add(prof.MaxLifetime).Format(time.RFC3339Nano)}
	if cfg, err := client.GetVMConfig(ctx, ids[0]); err == nil {
		state.IP = cfg.IPv4()
	}
	return &pluginsdk.RecoverExecutorOperationResponse{Outcome: "found", Resource: descriptor(state)}, nil
}

func (p *Provider) clientForState(ctx context.Context, s State) (HostdAPI, error) {
	creds, err := p.credsForState(ctx, s)
	if err != nil {
		return nil, err
	}
	return p.NewClient(s.APIBaseURL, s.Project, creds.Token), nil
}

// AttachExecutorEnvironment re-binds to a retained, running VM.
func (p *Provider) AttachExecutorEnvironment(ctx context.Context, req *pluginsdk.AttachExecutorEnvironmentRequest) (*pluginsdk.AttachExecutorEnvironmentResponse, error) {
	s, err := stateFrom(req.GetResource())
	if err != nil {
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerError("resource_invalid", 0)}, nil
	}
	client, err := p.clientForState(ctx, s)
	if err != nil {
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerError("credentials_unavailable", 30)}, nil
	}
	vm, err := client.GetVM(ctx, s.VMID)
	if hostd.IsNotFound(err) {
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerError("resource_not_found", 0)}, nil
	}
	if err != nil {
		return nil, err
	}
	if vm.Status != "running" || expired(s, p.Now()) {
		// A rebooted VM restarts agentctl with a fresh token, so the session
		// Kandev holds is gone; the spike does not resume stopped VMs.
		return &pluginsdk.AttachExecutorEnvironmentResponse{Error: providerError("not_running", 0)}, nil
	}
	return &pluginsdk.AttachExecutorEnvironmentResponse{Resource: descriptor(s)}, nil
}

// InspectExecutorEnvironment maps the hostd power state.
func (p *Provider) InspectExecutorEnvironment(ctx context.Context, req *pluginsdk.InspectExecutorEnvironmentRequest) (*pluginsdk.InspectExecutorEnvironmentResponse, error) {
	s, err := stateFrom(req.GetResource())
	if err != nil {
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: "unknown", Reason: "resource_invalid"}, nil
	}
	client, err := p.clientForState(ctx, s)
	if err != nil {
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: "unknown", Reason: "credentials_unavailable", ExpiresAt: s.ExpiresAt}, nil
	}
	vm, err := client.GetVM(ctx, s.VMID)
	if hostd.IsNotFound(err) {
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: "absent", Reason: "resource_not_found"}, nil
	}
	if err != nil {
		return &pluginsdk.InspectExecutorEnvironmentResponse{State: "unknown", Reason: "api_unavailable", ExpiresAt: s.ExpiresAt}, nil
	}
	state := "unknown"
	switch vm.Status {
	case "running":
		state = "running"
	case "stopped":
		state = "suspended"
	}
	return &pluginsdk.InspectExecutorEnvironmentResponse{State: state, ExpiresAt: s.ExpiresAt}, nil
}

// ResolveExecutorConnection mints a lease for the control port or an
// instance port: base URL https://<ip>:<edge>/p/<port>, credential in a
// header, verified on the VM by hostd-edge.
func (p *Provider) ResolveExecutorConnection(ctx context.Context, req *pluginsdk.ResolveExecutorConnectionRequest) (*pluginsdk.ResolveExecutorConnectionResponse, error) {
	port := req.GetRuntimePort()
	if req.GetPurpose() != "agentctl" || port == 0 || port > 65535 {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError("unsupported_connection", 0)}, nil
	}
	s, err := stateFrom(req.GetResource())
	if err != nil || s.IP == "" || !s.Bootstrapped {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError("resource_not_ready", 5)}, nil
	}
	if port != 8765 && (port < instancePortBase || port > instancePortMax) {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError("unsupported_port", 0)}, nil
	}
	if expired(s, p.Now()) {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError("environment_expired", 0)}, nil
	}
	creds, err := p.credsForState(ctx, s)
	if err != nil {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError("credentials_unavailable", 5)}, nil
	}
	now := p.Now()
	exp := now.Add(LeaseLifetime)
	if e, err := time.Parse(time.RFC3339Nano, s.ExpiresAt); err == nil && e.Before(exp) {
		exp = e
	}
	gen := "hostd-" + strconv.FormatInt(now.UnixNano(), 36)
	handle := Handle(s.Project, s.VMID)
	key := lease.DeriveVMKey(creds.LeaseSecret, req.GetContext().GetOperationId())
	tok, err := lease.Mint(key, lease.Claims{Resource: handle, Port: port, Generation: gen, Expires: exp.Unix()})
	if err != nil {
		return nil, err
	}
	l := lease.Lease{
		BaseURL:          fmt.Sprintf("https://%s/p/%d", net.JoinHostPort(s.IP, strconv.Itoa(s.EdgePort)), port),
		HTTPHeaders:      map[string]string{lease.Header: tok},
		WebSocketHeaders: map[string]string{lease.Header: tok},
		ExpiresAt:        exp.UTC().Format(time.RFC3339Nano),
		Generation:       gen,
	}
	if err := lease.ValidateForKandev(l, now); err != nil {
		return &pluginsdk.ResolveExecutorConnectionResponse{Error: providerError("lease_invalid", 0)}, nil
	}
	return &pluginsdk.ResolveExecutorConnectionResponse{Lease: &pluginsdk.ExecutorConnectionLease{
		BaseUrl: l.BaseURL, HttpHeaders: l.HTTPHeaders, WebsocketHeaders: l.WebSocketHeaders,
		ExpiresAt: l.ExpiresAt, Generation: l.Generation,
	}}, nil
}

// DestroyExecutorEnvironment stops and deletes the VM and releases its IPv4.
// confirmed_absent is set only when hostd answers 404 for the VM and the
// address is no longer reserved on the project.
func (p *Provider) DestroyExecutorEnvironment(ctx context.Context, req *pluginsdk.DestroyExecutorEnvironmentRequest) (*pluginsdk.DestroyExecutorEnvironmentResponse, error) {
	if req.GetResource() == nil || req.GetResource().GetResourceHandle() == "" {
		return &pluginsdk.DestroyExecutorEnvironmentResponse{ConfirmedAbsent: true}, nil
	}
	s, err := stateFrom(req.GetResource())
	if err != nil {
		return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerError("resource_invalid", 0)}, nil
	}
	client, err := p.clientForState(ctx, s)
	if err != nil {
		return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerError("credentials_unavailable", 30)}, nil
	}
	t := p.Now()
	absent, err := client.DestroyVM(ctx, s.VMID, p.PollEvery)
	if err != nil || !absent {
		// Kandev's launch-failure cleanup allows 30 s; a slow stop finishes on
		// the next (idempotent) Destroy.
		p.logf("vm=%d destroy pending after %s: %v", s.VMID, p.Now().Sub(t).Round(time.Millisecond), err)
		return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerError("cleanup_in_progress", 15)}, nil
	}
	if s.IP != "" {
		ips, err := client.ListPublicIPs(ctx)
		if err != nil {
			return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerError("cleanup_unconfirmed", 15)}, nil
		}
		for _, ip := range ips {
			if ip.IP == s.IP {
				p.logf("vm=%d deleted but %s is still reserved (status %s)", s.VMID, ip.IP, ip.Status)
				return &pluginsdk.DestroyExecutorEnvironmentResponse{Error: providerError("public_ip_retained", 60)}, nil
			}
		}
	}
	p.logf("vm=%d destroyed in %s", s.VMID, p.Now().Sub(t).Round(time.Millisecond))
	return &pluginsdk.DestroyExecutorEnvironmentResponse{ConfirmedAbsent: true}, nil
}

func (p *Provider) progress(ctx context.Context, cb pluginsdk.ExecutorProviderHostAPI, rc *pluginsdk.ExecutorProviderRequestContext, stage string, done, total uint32) {
	if cb == nil {
		return
	}
	_, _ = cb.ReportExecutorProgress(ctx, &pluginsdk.ReportExecutorProgressRequest{Context: rc, Stage: stage, Completed: done, Total: total})
}

func (p *Provider) checkpoint(ctx context.Context, cb pluginsdk.ExecutorProviderHostAPI, rc *pluginsdk.ExecutorProviderRequestContext, s State, phase string) {
	if cb == nil {
		return
	}
	if _, err := cb.CheckpointExecutorResource(ctx, &pluginsdk.CheckpointExecutorResourceRequest{Context: rc, Resource: descriptor(s), Phase: phase}); err != nil {
		p.logf("vm=%d checkpoint %s rejected: %v", s.VMID, phase, err)
	}
}

func (p *Provider) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

func randomPassword() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + "aA1!"
}

func short(op string) string {
	if len(op) > 8 {
		return op[:8]
	}
	return op
}
