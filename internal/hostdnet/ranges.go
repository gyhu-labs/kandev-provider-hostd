// Package hostdnet holds the one place where hostd.cloud's public address
// space is written down. The CA's NameConstraints, the profile default for
// permitted_cidrs and the deployment's egress/Access rules all derive from it.
//
// Source: the prefixes announced by AS60594 (T-Band Sp. z o.o., hostd.cloud),
// RIPEstat "announced-prefixes", checked 2026-11-27 for 2026-05-01 onwards:
//
//	IPv4 38.56.199.0/24    VM WAN addresses (seen live: 38.56.199.191)
//	IPv4 155.133.32.0/24
//	IPv6 2a0e:7d80::/48    since 2026-09-12 (earlier 2a06:1e00:2f::/48 until 2026-09-14)
//
// VMs are created with wan_mode=ipv4, so only the IPv4 prefixes go into the
// CA. The IPv6 prefix matters only for allow-lists of traffic that may leave
// a VM over IPv6 (e.g. a Cloudflare Access IP rule).
//
// Re-check before a new CA ceremony and at least every quarter:
//
//	curl -s 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS60594&starttime=<date>' |
//	  jq -r '.data.prefixes[] | [.prefix, .timelines[-1].endtime] | @tsv'
//
// A prefix that appears here later than the CA was cut is not covered by the
// CA: VMs on it fail with ip_outside_ca_constraints until a new CA is issued.
package hostdnet

import "strings"

// DefaultPermittedCIDRs is the IPv4 space a hostd VM can get a WAN address
// from (comma separated, the profile's permitted_cidrs format).
const DefaultPermittedCIDRs = "38.56.199.0/24,155.133.32.0/24"

// IPv6Prefixes are hostd's announced IPv6 prefixes. They are not used for
// certificates (VMs are IPv4-only); deployments use them for allow-lists.
const IPv6Prefixes = "2a0e:7d80::/48"

// SourceAS is the autonomous system the prefixes are taken from.
const SourceAS = "AS60594"

// Split turns a comma/space separated CIDR list into its items.
func Split(list string) []string {
	return strings.Fields(strings.ReplaceAll(list, ",", " "))
}
