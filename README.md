# kandev-provider-hostd

> **Status: pilot (v0.1.x).** A Kandev remote executor provider backed by
> [hostd.cloud](https://hostd.cloud) VMs. The provider contract was proven
> against real hostd VMs by a harness; the first supervised run inside a live
> Kandev is the v0.1.0 pilot. Expect contract churn with every Kandev release.

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

Kandev trusts the CA through `SSL_CERT_FILE` pointing at a bundle of the
image's system roots plus this CA (a deployment change outside this repo).
Go reads `SSL_CERT_FILE` instead of its default bundle file, so the bundle
must keep the system roots. Let's Encrypt IP certificates are the documented
alternative; they were rejected because hostd reuses IPv4 addresses across
customers immediately.

### hostd address space (one config value)

`internal/hostdnet` is the only place the hostd ranges are written down:
IPv4 `38.56.199.0/24` and `155.133.32.0/24` (CA constraints, profile default
`permitted_cidrs`), IPv6 `2a0e:7d80::/48` (allow-lists only; VMs are created
IPv4-only). They are the prefixes announced by **AS60594** (T-Band, hostd).
Re-check them before every CA ceremony and quarterly:

```
curl -s 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS60594&starttime=<YYYY-MM-DD>' |
  jq -r '.data.prefixes[] | [.prefix, .timelines[0].starttime, .timelines[-1].endtime] | @tsv'
```

A new IPv4 prefix needs a new CA (`hostd-ca init`), the new range in the
deployment's egress policy and Access allow-list, and a profile update.

### CA ceremony

```
go run ./cmd/hostd-ca init --cert hostd-ca.crt --key hostd-ca.key   # ECDSA P-256, ~2 years, hostdnet ranges
go run ./cmd/hostd-ca show --cert hostd-ca.crt                      # public summary + fingerprint
```

The key file is written 0600 and never printed. Move it into the secret
store (it becomes the profile secret `ca_key_pem`) and `shred -u` the file.

## Git credential broker relay

Kandev gives a remote environment one broker URL,
`<githubCredentialBroker.publicBaseUrl>/api/v1/git/credentials/resolve`, and
the bootstrap `api_url` from the same base. When that base is an in-cluster
name (it also serves the Kubernetes executors), a hostd VM cannot reach it.
Set the profile option `broker_upstream` to the public origin of the same
Kandev (e.g. `https://kandev.example.com`). The VM then gets:

- `/etc/hosts`: the broker name → `127.0.0.1`;
- `hostd-edge` serving `127.0.0.1:443` with a VM-local certificate whose
  anchor CA is name-constrained to that one host name (its key is never
  written to disk) and trusted only in the VM's system store;
- forwarding of exactly `GET|POST /api/v1/git/credentials/resolve` and
  `POST /api/v1/git/credentials/reissue` to `broker_upstream`, with no
  cookies, Authorization or forwarding headers, no redirects followed.

The upstream must let the hostd address space reach those two paths (for
example a path-scoped Cloudflare Access bypass for the hostd ranges). No
other Kandev path is used by a regular task session: agentctl talks to
Kandev only over the connection Kandev opens to it; `KANDEV_API_URL` is used
only by the Office CLI (`agentctl kandev …`), which this provider does not
support.

## Package and release

`scripts/package.sh` builds the package Kandev installs
(`kandev-provider-hostd-<version>.tar.gz`: `manifest.yaml`,
`server/plugin-linux-amd64`, `server/hostd-edge-linux-amd64`, README,
LICENSE, `checksums.txt`). It is reproducible (static binaries without build
IDs, mtimes from the last commit). CI runs `kandev-sdk-check` and verifies
the archive with Kandev's own `pkgtar.Verify` and `pkgtar.Install` at the
pinned Kandev release. Pushing tag `vX.Y.Z` (equal to the manifest
`version`) publishes the package and its `.sha256` as release assets.

Install (Kandev admin, PAT or session):

```
POST /api/plugins/install  {"url": "https://github.com/gyhu-labs/kandev-provider-hostd/releases/download/vX.Y.Z/kandev-provider-hostd-X.Y.Z.tar.gz"}
```

## Layout

```
cmd/kandev-provider-hostd  plugin binary (pluginsdk.Serve)
cmd/hostd-edge             per-VM TLS front (csr | relay-init | serve), uploaded by the plugin
cmd/hostd-ca               CA ceremony (init | show)
cmd/plugin-pack            Kandev plugin package writer/verifier
cmd/spike                  live harness: Provision → Resolve → HTTPS → Destroy on real hostd
internal/hostd             hostd API client (429 Retry-After, "No free public IPv4" retry, adopt-by-name)
internal/hostdnet          hostd address space (AS60594), the single source for ranges
internal/pkgpack           package format (mirror of Kandev's pkgtar rules)
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
