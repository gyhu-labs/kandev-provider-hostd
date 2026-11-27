package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/tlsca"
	"github.com/kdlbs/kandev/pluginsdk"
	"golang.org/x/crypto/ssh"
)

// Profile option and secret keys (see manifest.yaml profile_schema).
const (
	cfgProject        = "project"
	cfgAPIBaseURL     = "api_base_url"
	cfgCPUMode        = "cpu_mode"
	cfgCores          = "cores"
	cfgRAMGB          = "ram_gb"
	cfgDiskGB         = "disk_gb"
	cfgImage          = "image"
	cfgMaxLifetime    = "max_lifetime"
	cfgSSHKeyID       = "ssh_key_id"
	cfgSSHUser        = "ssh_user"
	cfgPermittedCIDRs = "permitted_cidrs"
	cfgEdgePort       = "edge_port"
	cfgInstallDocker  = "install_docker"
	cfgCACertPEM      = "ca_cert_pem"

	secHostdToken   = "hostd_api_token"
	secCAKeyPEM     = "ca_key_pem"
	secSSHKey       = "ssh_private_key"
	secLeaseSecret  = "lease_secret"
	defaultImage    = "debian-13-amd64.qcow2"
	defaultCIDRs    = "38.56.199.0/24"
	defaultLifetime = 8 * time.Hour
	// MaxLifetime is the manifest's maximum_lifetime_seconds (7 days), equal
	// to the leaf certificate cap so a VM never outlives its certificate.
	MaxLifetime = 7 * 24 * time.Hour
)

// Profile is a parsed, validated provider profile (non-secret part).
type Profile struct {
	ID             string
	Project        string
	APIBaseURL     string
	CPUMode        string
	Cores          int64
	RAMGB          int64
	DiskGB         int64
	Image          string
	MaxLifetime    time.Duration
	SSHKeyID       int64
	SSHUser        string
	PermittedCIDRs []*net.IPNet
	EdgePort       int
	InstallDocker  bool
	CACertPEM      string
}

// Secrets are the transient credentials. They are never written to resource
// state, logs, command arguments or URLs.
type Secrets struct {
	HostdToken  string `json:"hostd_api_token"`
	CAKeyPEM    string `json:"ca_key_pem"`
	SSHKey      string `json:"ssh_private_key"`
	LeaseSecret string `json:"lease_secret"`
	// CACertPEM is public; it is stored with the secrets only so that
	// profile-less RPCs can rebuild the CA after a plugin restart.
	CACertPEM string `json:"ca_cert_pem,omitempty"`
}

func (s Secrets) complete() bool {
	return s.HostdToken != "" && s.CAKeyPEM != "" && s.SSHKey != "" && len(s.LeaseSecret) >= 32
}

func secretsFrom(values map[string]string) Secrets {
	return Secrets{HostdToken: values[secHostdToken], CAKeyPEM: values[secCAKeyPEM], SSHKey: values[secSSHKey], LeaseSecret: values[secLeaseSecret]}
}

func (s Secrets) marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func fieldErr(field, code string) *pluginsdk.ExecutorProviderFieldError {
	return &pluginsdk.ExecutorProviderFieldError{Field: field, Code: code, MessageId: "profile." + field + "." + code}
}

// ParseProfile validates the non-secret config and returns field errors.
func ParseProfile(snap *pluginsdk.ExecutorProfileSnapshot) (*Profile, []*pluginsdk.ExecutorProviderFieldError) {
	c := map[string]string{}
	if snap != nil {
		c = snap.GetConfig()
	}
	get := func(k, def string) string {
		if v := strings.TrimSpace(c[k]); v != "" {
			return v
		}
		return def
	}
	var errs []*pluginsdk.ExecutorProviderFieldError
	intField := func(k string, def, lo, hi int64) int64 {
		raw := get(k, strconv.FormatInt(def, 10))
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			// The profile editor may send integers as JSON numbers ("2.0" never, "2" usually).
			f, ferr := strconv.ParseFloat(raw, 64)
			if ferr != nil || f != float64(int64(f)) {
				errs = append(errs, fieldErr(k, "invalid"))
				return def
			}
			n = int64(f)
		}
		if n < lo || n > hi {
			errs = append(errs, fieldErr(k, "out_of_range"))
		}
		return n
	}
	p := &Profile{
		Project:    get(cfgProject, ""),
		APIBaseURL: get(cfgAPIBaseURL, ""),
		CPUMode:    get(cfgCPUMode, "light"),
		Image:      get(cfgImage, defaultImage),
		SSHUser:    get(cfgSSHUser, "kandev"),
		CACertPEM:  c[cfgCACertPEM],
	}
	if snap != nil {
		p.ID = snap.GetProfileId()
	}
	if p.Project == "" {
		errs = append(errs, fieldErr(cfgProject, "required"))
	}
	if p.CPUMode != "light" && p.CPUMode != "regular" {
		errs = append(errs, fieldErr(cfgCPUMode, "invalid"))
	}
	// hostd: max 8 vCPU per VM until a limit raise; RAM up to 4 GB per vCPU budget.
	p.Cores = intField(cfgCores, 2, 1, 8)
	p.RAMGB = intField(cfgRAMGB, 4, 1, 64)
	p.DiskGB = intField(cfgDiskGB, 20, 10, 500)
	p.SSHKeyID = intField(cfgSSHKeyID, 0, 1, 1<<40)
	p.EdgePort = int(intField(cfgEdgePort, 8443, 1024, 65535))
	p.InstallDocker = get(cfgInstallDocker, "true") != "false"
	lifetime, err := time.ParseDuration(get(cfgMaxLifetime, defaultLifetime.String()))
	if err != nil || lifetime <= 0 || lifetime > MaxLifetime {
		errs = append(errs, fieldErr(cfgMaxLifetime, "invalid"))
		lifetime = defaultLifetime
	}
	p.MaxLifetime = lifetime
	nets, err := tlsca.ParseCIDRs(strings.Fields(strings.ReplaceAll(get(cfgPermittedCIDRs, defaultCIDRs), ",", " ")))
	if err != nil {
		errs = append(errs, fieldErr(cfgPermittedCIDRs, "invalid"))
	}
	p.PermittedCIDRs = nets
	if p.CACertPEM == "" {
		errs = append(errs, fieldErr(cfgCACertPEM, "required"))
	} else if cert, err := tlsca.ParseCertificatePEM([]byte(p.CACertPEM)); err != nil || tlsca.CheckConstrained(cert) != nil {
		errs = append(errs, fieldErr(cfgCACertPEM, "not_constrained"))
	}
	return p, errs
}

// Credentials are the parsed secrets.
type Credentials struct {
	Token       string
	CA          *tlsca.CA
	SSHSigner   ssh.Signer
	LeaseSecret []byte
}

// ParseCredentials loads the secrets against the profile's CA certificate.
func ParseCredentials(p *Profile, s Secrets) (*Credentials, error) {
	if !s.complete() {
		return nil, errors.New("provider credentials are incomplete")
	}
	ca, err := tlsca.Load([]byte(p.CACertPEM), []byte(s.CAKeyPEM))
	if err != nil {
		return nil, err
	}
	// The CA's own constraints must cover every range the profile allows,
	// otherwise a leaf could be issued that Kandev would reject.
	for _, n := range p.PermittedCIDRs {
		if !ca.Permits(n.IP) {
			return nil, fmt.Errorf("permitted CIDR %s is outside the CA constraints", n)
		}
	}
	signer, err := ssh.ParsePrivateKey([]byte(s.SSHKey))
	if err != nil {
		return nil, errors.New("ssh private key is invalid")
	}
	return &Credentials{Token: s.HostdToken, CA: ca, SSHSigner: signer, LeaseSecret: []byte(s.LeaseSecret)}, nil
}

// Bootstrap is Kandev's bootstrap_json (lifecycle/executor_plugin.go:259-262).
type Bootstrap struct {
	Nonce       string `json:"nonce"`
	RuntimePort uint32 `json:"runtime_port"`
	APIURL      string `json:"api_url"`
	ExecutionID string `json:"execution_id"`
	ArtifactID  string `json:"artifact_id"`
}

func parseBootstrap(raw string) (*Bootstrap, error) {
	var b Bootstrap
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, errors.New("bootstrap is not valid JSON")
	}
	if b.Nonce == "" || b.RuntimePort == 0 || b.RuntimePort > 65535 {
		return nil, errors.New("bootstrap nonce and runtime_port are required")
	}
	if b.ArtifactID == "" {
		b.ArtifactID = "agentctl"
	}
	return &b, nil
}
