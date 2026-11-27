package hostd

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// CreateVMInput is the POST /cloud/project/<uuid>/vm/ body. hostd has no
// user-data/cloud-init field: everything else happens over SSH.
type CreateVMInput struct {
	Hostname  string  `json:"hostname"`
	Username  string  `json:"username,omitempty"`
	Password  string  `json:"password"`
	SSHKeyIDs []int64 `json:"ssh_key_ids,omitempty"`
	Cores     int64   `json:"cores"`
	RAMGB     int64   `json:"ram_gb"`
	OSDiskGB  int64   `json:"os_disk_gb"`
	OSImage   string  `json:"os_image"`
	CPUMode   string  `json:"cpu_mode"`
	WANMode   string  `json:"wan_mode"`
}

// VM is the subset of GET .../vm/<id>/ and list entries we use.
type VM struct {
	VMID    int64  `json:"vmid"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	CPUMode string `json:"cpu_mode"`
}

// VMConfig is GET .../vm/<id>/config/current/.
type VMConfig struct {
	Name     string `json:"name"`
	Cores    int64  `json:"cores"`
	RAMGB    int64  `json:"ram_gb"`
	OSDiskGB *int64 `json:"os_disk_gb"`
	WAN      *struct {
		IPv4 *string `json:"ipv4"`
		IPv6 *string `json:"ipv6"`
	} `json:"wan"`
}

// IPv4 returns the WAN IPv4 or "".
func (c *VMConfig) IPv4() string {
	if c == nil || c.WAN == nil || c.WAN.IPv4 == nil {
		return ""
	}
	return *c.WAN.IPv4
}

// PublicIP is one entry of GET .../public-ips/.
type PublicIP struct {
	IP     string `json:"ip"`
	VMID   *int64 `json:"vmid"`
	Status string `json:"status"`
}

func (c *Client) vmsPath() string { return "/cloud/project/" + c.Project + "/vm/" }
func (c *Client) vmPath(vmid int64) string {
	return fmt.Sprintf("/cloud/project/%s/vm/%d/", c.Project, vmid)
}

// ListVMs lists the project's VMs.
func (c *Client) ListVMs(ctx context.Context) ([]VM, error) {
	var vms []VM
	return vms, c.do(ctx, http.MethodGet, c.vmsPath(), nil, &vms)
}

// VMIDsByName returns the ids of VMs whose name equals hostname.
func (c *Client) VMIDsByName(ctx context.Context, hostname string) ([]int64, error) {
	vms, err := c.ListVMs(ctx)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for _, vm := range vms {
		if vm.Name == hostname {
			ids = append(ids, vm.VMID)
		}
	}
	return ids, nil
}

// GetVM reads one VM; a deleted VM returns an *Error with Status 404.
func (c *Client) GetVM(ctx context.Context, vmid int64) (*VM, error) {
	var vm VM
	if err := c.do(ctx, http.MethodGet, c.vmPath(vmid), nil, &vm); err != nil {
		return nil, err
	}
	return &vm, nil
}

// GetVMConfig reads the current config (size, WAN IPs).
func (c *Client) GetVMConfig(ctx context.Context, vmid int64) (*VMConfig, error) {
	var cfg VMConfig
	if err := c.do(ctx, http.MethodGet, c.vmPath(vmid)+"config/current/", nil, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SetPower runs start, shutdown or stop.
func (c *Client) SetPower(ctx context.Context, vmid int64, action string) error {
	return c.do(ctx, http.MethodPost, c.vmPath(vmid)+"power/"+action+"/", nil, nil)
}

// DeleteVM deletes a stopped VM with its disks; releasePublicIP returns the
// IPv4 to the pool (otherwise it stays reserved, and billed, on the project).
func (c *Client) DeleteVM(ctx context.Context, vmid int64, releasePublicIP bool) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("%s?release_public_ip=%t", c.vmPath(vmid), releasePublicIP), nil, nil)
}

// ListPublicIPs lists addresses reserved on the project.
func (c *Client) ListPublicIPs(ctx context.Context) ([]PublicIP, error) {
	var ips []PublicIP
	return ips, c.do(ctx, http.MethodGet, "/cloud/project/"+c.Project+"/public-ips/", nil, &ips)
}

// WaitStatus polls until the VM reports want.
func (c *Client) WaitStatus(ctx context.Context, vmid int64, want string, every time.Duration) error {
	for {
		vm, err := c.GetVM(ctx, vmid)
		if err != nil {
			return err
		}
		if vm.Status == want {
			return nil
		}
		if err := c.Sleep(ctx, every); err != nil {
			return fmt.Errorf("vm %d is %q, want %q: %w", vmid, vm.Status, want, err)
		}
	}
}

// CreateOutcome says how EnsureVM obtained the VM.
type CreateOutcome string

const (
	OutcomeCreated CreateOutcome = "created"
	OutcomeAdopted CreateOutcome = "adopted"
)

// EnsureVM is the idempotent create: the hostname is derived from the
// operation identity, so an existing VM with that name is this operation's
// earlier allocation and is adopted rather than duplicated. An interrupted
// POST is resolved by listing again (as the Terraform provider does). The
// transient "No free public IPv4" answer is retried with backoff until ctx
// ends; quota errors are returned at once.
func (c *Client) EnsureVM(ctx context.Context, in CreateVMInput, ipv4RetryEvery time.Duration) (int64, CreateOutcome, int, error) {
	retries := 0
	for {
		ids, err := c.VMIDsByName(ctx, in.Hostname)
		if err != nil {
			return 0, "", retries, err
		}
		switch len(ids) {
		case 0:
		case 1:
			return ids[0], OutcomeAdopted, retries, nil
		default:
			return 0, "", retries, fmt.Errorf("hostd: %d VMs are named %q; refusing to pick one", len(ids), in.Hostname)
		}
		var out struct {
			VMID int64 `json:"vmid"`
		}
		err = c.do(ctx, http.MethodPost, c.vmsPath(), in, &out)
		switch {
		case err == nil:
			return out.VMID, OutcomeCreated, retries, nil
		case IsInterrupted(err):
			after, findErr := c.VMIDsByName(context.WithoutCancel(ctx), in.Hostname)
			if findErr == nil && len(after) == 1 {
				return after[0], OutcomeAdopted, retries, nil
			}
			return 0, "", retries, err
		case IsNoFreeIPv4(err):
			retries++
			wait := ipv4RetryEvery * time.Duration(min(retries, 4))
			if err := c.Sleep(ctx, wait); err != nil {
				return 0, "", retries, fmt.Errorf("hostd: no free public IPv4 after %d retries: %w", retries, err)
			}
		default:
			return 0, "", retries, err
		}
	}
}

// DestroyVM stops (hard) and deletes the VM, releasing its IPv4. It returns
// confirmedAbsent=true only when a follow-up GET answers 404, or when the
// vmid now belongs to a VM with another name. hostd reuses vmids (seen live:
// four consecutive VMs were all 1073), so a stale handle must never delete a
// different environment's VM: expectName guards every destructive call.
func (c *Client) DestroyVM(ctx context.Context, vmid int64, expectName string, poll time.Duration) (bool, error) {
	vm, err := c.GetVM(ctx, vmid)
	if IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if expectName != "" && vm.Name != expectName {
		return true, nil
	}
	if vm.Status != "stopped" {
		if err := c.SetPower(ctx, vmid, "stop"); err != nil && !IsNotFound(err) {
			return false, err
		}
		if err := c.WaitStatus(ctx, vmid, "stopped", poll); err != nil {
			if IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
	}
	if err := c.DeleteVM(ctx, vmid, true); err != nil && !IsNotFound(err) {
		return false, err
	}
	for {
		_, err := c.GetVM(ctx, vmid)
		if IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if err := c.Sleep(ctx, poll); err != nil {
			return false, err
		}
	}
}
