package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
)

// StateVersion is the only resource-state version this build reads/writes.
const StateVersion = 1

// State is the durable, non-secret resource state. Its JSON keys must match
// manifest.yaml resource_state_schema exactly (additionalProperties: false).
type State struct {
	VMID          int64  `json:"vmid"`
	IP            string `json:"ip,omitempty"`
	Project       string `json:"project"`
	Hostname      string `json:"hostname"`
	ProfileID     string `json:"profile_id"`
	APIBaseURL    string `json:"api_base_url,omitempty"`
	SSHUser       string `json:"ssh_user"`
	SSHHostKey    string `json:"ssh_host_key,omitempty"`
	EdgePort      int    `json:"edge_port"`
	CPUMode       string `json:"cpu_mode"`
	Cores         int64  `json:"cores"`
	RAMGB         int64  `json:"ram_gb"`
	CreatedAt     string `json:"created_at"`
	ExpiresAt     string `json:"expires_at"`
	LeafExpiresAt string `json:"leaf_expires_at,omitempty"`
	Bootstrapped  bool   `json:"bootstrapped"`
}

// Hostname derives the VM name from the operation identity. The same
// operation always maps to the same hostd VM, which makes Provision and
// Recover idempotent without any plugin-side database.
func Hostname(operationID string) string {
	sum := sha256.Sum256([]byte("kandev-provider-hostd/op\x00" + operationID))
	return "kd-" + hex.EncodeToString(sum[:])[:24]
}

// Handle is the opaque resource handle: hostd:<project>:<vmid>.
func Handle(project string, vmid int64) string {
	return fmt.Sprintf("hostd:%s:%d", project, vmid)
}

func parseHandle(h string) (string, int64, error) {
	parts := strings.Split(h, ":")
	if len(parts) != 3 || parts[0] != "hostd" || parts[1] == "" {
		return "", 0, errors.New("resource handle is not a hostd handle")
	}
	vmid, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || vmid <= 0 {
		return "", 0, errors.New("resource handle has an invalid vmid")
	}
	return parts[1], vmid, nil
}

func capabilities() *pluginsdk.ExecutorProviderCapabilities {
	return &pluginsdk.ExecutorProviderCapabilities{
		Terminal: true, Files: true, Git: true, EmbeddedEditor: false, Preview: false,
		Reattach: true, Retention: "bounded", MaximumLifetimeSeconds: uint64(MaxLifetime.Seconds()),
	}
}

func descriptor(s State) *pluginsdk.ExecutorResourceDescriptor {
	raw, _ := json.Marshal(s)
	return &pluginsdk.ExecutorResourceDescriptor{
		ResourceHandle: Handle(s.Project, s.VMID), StateJson: string(raw), Platform: "linux-amd64",
		Capabilities: capabilities(), ExpiresAt: s.ExpiresAt, Retention: "bounded", StateVersion: StateVersion,
	}
}

func stateFrom(r *pluginsdk.ExecutorResourceDescriptor) (State, error) {
	var s State
	if r == nil || r.GetResourceHandle() == "" {
		return s, errors.New("resource is missing")
	}
	if v := r.GetStateVersion(); v != 0 && v != StateVersion {
		return s, fmt.Errorf("resource state version %d is unsupported", v)
	}
	project, vmid, err := parseHandle(r.GetResourceHandle())
	if err != nil {
		return s, err
	}
	if r.GetStateJson() != "" {
		if err := json.Unmarshal([]byte(r.GetStateJson()), &s); err != nil {
			return s, errors.New("resource state is invalid")
		}
	}
	if s.VMID == 0 {
		s.VMID = vmid
	}
	if s.Project == "" {
		s.Project = project
	}
	if s.VMID != vmid || s.Project != project {
		return s, errors.New("resource state does not match its handle")
	}
	return s, nil
}

func expired(s State, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, s.ExpiresAt)
	return err == nil && !now.Before(t)
}
