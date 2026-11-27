package provider

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// relayListen is where the VM-local broker relay listens. agentctl reaches it
// through an /etc/hosts entry for the broker name, on the default HTTPS port
// because Kandev's broker URL carries no port.
const relayListen = "127.0.0.1:443"

var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// ParseBrokerUpstream validates the broker_upstream profile option and
// returns its canonical origin (https://host[:port]).
func ParseBrokerUpstream(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("broker_upstream must be an https origin such as https://kandev.example.com")
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) == nil && !dnsName.MatchString(host) {
		return "", errors.New("broker_upstream host is invalid")
	}
	if p := u.Port(); p != "" {
		return "https://" + net.JoinHostPort(host, p), nil
	}
	return "https://" + host, nil
}

// relayTarget decides whether a VM needs the broker relay. Kandev derives
// the broker URL and the bootstrap api_url from the same publicBaseUrl
// (backendapp/orchestrator.go:652-672), so the broker host is api_url's host.
// No relay is needed when no upstream is configured or when that host is
// already the public upstream.
func relayTarget(apiURL, upstream string) (string, error) {
	if upstream == "" {
		return "", nil
	}
	u, err := url.Parse(apiURL)
	if err != nil || u.Hostname() == "" {
		return "", errors.New("bootstrap api_url has no host")
	}
	host := strings.ToLower(u.Hostname())
	up, _ := url.Parse(upstream)
	if host == strings.ToLower(up.Hostname()) {
		return "", nil
	}
	if p := u.Port(); p != "" && p != "443" {
		return "", fmt.Errorf("broker relay supports only port 443, api_url uses %s", p)
	}
	if net.ParseIP(host) != nil || !dnsName.MatchString(host) {
		return "", errors.New("broker relay needs a DNS host name in api_url")
	}
	return host, nil
}

// relaySetupScript creates the relay certificate on the VM, trusts its
// VM-local anchor in the system store (agentctl and curl use it) and points
// the broker name at loopback. host is validated by relayTarget.
func relaySetupScript(host string) string {
	return fmt.Sprintf(`set -e
command -v update-ca-certificates >/dev/null || { echo "update-ca-certificates is missing (package ca-certificates)" >&2; exit 1; }
%[1]s relay-init --dir %[2]s --host %[3]s
install -m 0644 %[2]s/relay-ca.crt /usr/local/share/ca-certificates/hostd-edge-relay.crt
update-ca-certificates --fresh >/dev/null 2>&1
tmp=$(mktemp)
grep -v ' # hostd-edge-relay$' /etc/hosts > "$tmp" || true
echo '127.0.0.1 %[3]s # hostd-edge-relay' >> "$tmp"
cat "$tmp" > /etc/hosts
rm -f "$tmp"`, edgePath, edgeDir, host)
}
