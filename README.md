# kandev-provider-hostd

> **Status: spike / not production.** Proves the hard parts of a Kandev remote
> executor provider backed by [hostd.cloud](https://hostd.cloud) VMs. It has
> never been installed into a running Kandev. Do not use it for real workloads.

A [Kandev](https://github.com/kdlbs/kandev) plugin that implements the
`pluginsdk.ExecutorProviderPlugin` contract (7 RPCs, contract version 1,
`github.com/kdlbs/kandev/pluginsdk v0.4.0`, Kandev ≥ 0.103.0):

| RPC | What it does here |
|---|---|
| ValidateExecutorProfile | Parses the profile (CPU class, size, image, lifetime, CA, SSH key id); no network calls. |
| ProvisionExecutorEnvironment | Creates the VM, or adopts it if it already exists: the VM hostname is `kd-` + a digest of the operation ID. Then bootstraps it over SSH (Docker, agentctl, TLS edge). |
| RecoverExecutorOperation | Looks the VM up by its derived hostname and answers `found`, `absent` or `unknown`. An API error answers `unknown`, never `absent`. |
| AttachExecutorEnvironment | Re-binds to a VM that is still running. |
| InspectExecutorEnvironment | Maps the hostd power state to `running`, `suspended`, `absent` or `unknown`. |
| ResolveExecutorConnection | Mints a short-lived HMAC lease for `https://<vm-ip>:8443/p/<port>` (the control port 8765 or an instance port 41001–41100). |
| DestroyExecutorEnvironment | Stops and deletes the VM and releases its IPv4. It sets `confirmed_absent` only when hostd returns 404 and the address is no longer reserved. |

## TLS without domains: a name-constrained private CA

Kandev accepts only HTTPS lease URLs. It allows IP-literal hosts and verifies
certificates against the process's default roots. This provider holds an
offline CA whose certificate carries **critical X.509 NameConstraints**: it
permits only the configured iPAddress ranges (the hostd public IPv4 block,
default `38.56.199.0/24`) and excludes every DNS name, e-mail address and URI.

For each VM:

1. The VM generates its own key and CSR (`hostd-edge csr`).
2. The plugin signs a leaf with exactly one IP SAN, valid for at most 7 days.
3. `hostd-edge serve` terminates TLS on the public port and checks the lease
   header. It then forwards to agentctl, which listens on `127.0.0.1` only.

Go's verifier enforces the constraints. A leaked CA key therefore cannot mint
a certificate that a client trusting this CA would accept for any hostname or
for an address outside the range. `internal/tlsca/ca_test.go` covers this.

Kandev would trust the CA through `SSL_CERT_FILE`/`SSL_CERT_DIR`. That is a
deployment change outside this repo. Let's Encrypt IP certificates are the
documented alternative (see the spike report).

## Layout

```
cmd/kandev-provider-hostd  plugin binary (pluginsdk.Serve)
cmd/hostd-edge             per-VM TLS front (csr | serve), uploaded by the plugin
cmd/spike                  live harness: Provision → Resolve → HTTPS → Destroy on real hostd
internal/hostd             hostd API client (429 Retry-After, "No free public IPv4" retry, adopt-by-name)
internal/tlsca             name-constrained CA, leaf issuance
internal/lease             lease tokens + a mirror of Kandev's lease validation rules
internal/edge              edge reverse proxy
internal/remote            SSH (no user-data on hostd)
internal/provider          the 7 RPCs, profile/state, bootstrap
package/manifest.yaml      plugin manifest (executor_providers, schemas)
```

## Secrets

The hostd API token, the CA key, the SSH private key and the lease secret
arrive as profile `SecretValues`. Kandev sends a profile only on Validate,
Provision and Recover. Attach, Inspect, Resolve and Destroy carry none. The
plugin therefore keeps the secrets in Kandev's plugin-owned secret store
(`Host.SetSecret`, `capabilities.secrets: true`), keyed by profile ID. Secrets
are never written to resource state, logs, command arguments or URLs. The
bootstrap nonce and the per-VM lease key reach the VM over SSH stdin, into
0600 files.

## Development

```
go vet ./... && go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/hostd-edge-linux-amd64 ./cmd/hostd-edge
HOSTD_API_TOKEN=… go run ./cmd/spike -project <uuid> -ssh-key-id <id> -ssh-key <file> \
    -agentctl <agentctl-linux-amd64> -edge bin/hostd-edge-linux-amd64   # creates a billed VM
```

## License

AGPL-3.0-only, because it links Kandev's AGPL `pluginsdk`.
