package provider

import (
	"strings"
	"testing"
)

func TestRelayTarget(t *testing.T) {
	for _, tc := range []struct {
		api, upstream, want string
		err                 bool
	}{
		{"https://kandev-broker.kandev.svc.lab.example.com/api/v1", "", "", false},
		{"https://kandev-broker.kandev.svc.lab.example.com/api/v1", "https://kandev.example.com", "kandev-broker.kandev.svc.lab.example.com", false},
		{"https://KANDEV.example.com/api/v1", "https://kandev.example.com", "", false}, // already public: no relay
		{"https://kandev-broker.internal:8443/api/v1", "https://kandev.example.com", "", true},
		{"https://10.0.0.5/api/v1", "https://kandev.example.com", "", true},
		{"https://bad_name.example/api/v1", "https://kandev.example.com", "", true},
		{"", "https://kandev.example.com", "", true},
	} {
		got, err := relayTarget(tc.api, tc.upstream)
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("relayTarget(%q,%q) = %q,%v; want %q, err=%v", tc.api, tc.upstream, got, err, tc.want, tc.err)
		}
	}
}

func TestParseBrokerUpstream(t *testing.T) {
	good := map[string]string{
		"https://kandev.example.com":      "https://kandev.example.com",
		"https://Kandev.Example.com/":     "https://kandev.example.com",
		"https://kandev.example.com:8443": "https://kandev.example.com:8443",
	}
	for in, want := range good {
		if got, err := ParseBrokerUpstream(in); err != nil || got != want {
			t.Errorf("ParseBrokerUpstream(%q) = %q,%v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"http://kandev.example.com", "https://kandev.example.com/api", "https://u:p@kandev.example.com", "https://kandev.example.com?x=1", "kandev.example.com"} {
		if _, err := ParseBrokerUpstream(in); err == nil {
			t.Errorf("ParseBrokerUpstream(%q) accepted", in)
		}
	}
}

func TestRelaySetupScriptQuotesOnlyValidatedHost(t *testing.T) {
	s := relaySetupScript("kandev-broker.example.com")
	for _, want := range []string{"relay-init --dir /etc/hostd-edge --host kandev-broker.example.com", "update-ca-certificates --fresh", "127.0.0.1 kandev-broker.example.com # hostd-edge-relay"} {
		if !strings.Contains(s, want) {
			t.Errorf("setup script lacks %q", want)
		}
	}
}

func TestProvisionPassesRelayOnlyWhenNeeded(t *testing.T) {
	f := newFixture(t)
	p := f.provider()
	// The fixture's bootstrap api_url is https://kandev.example/api... (public).
	f.cfg[cfgBrokerUpstream] = "https://kandev.example"
	if r := f.provision(t, p, "op-relay-1"); r.GetError() != nil {
		t.Fatalf("provision: %v", r.GetError())
	}
	if f.boot.last.RelayHost != "" {
		t.Fatalf("no relay expected when api_url is already the upstream, got %q", f.boot.last.RelayHost)
	}
	f.cfg[cfgBrokerUpstream] = "https://public.example"
	if r := f.provision(t, p, "op-relay-2"); r.GetError() != nil {
		t.Fatalf("provision: %v", r.GetError())
	}
	if f.boot.last.RelayHost != "kandev.example" || f.boot.last.RelayUpstream != "https://public.example" {
		t.Fatalf("relay = %q -> %q", f.boot.last.RelayHost, f.boot.last.RelayUpstream)
	}
	f.cfg[cfgBrokerUpstream] = "http://insecure.example"
	r := f.provision(t, p, "op-relay-3")
	if r.GetError().GetCode() != "invalid_profile" {
		t.Fatalf("an http upstream must be rejected as invalid_profile, got %v", r.GetError())
	}
}
