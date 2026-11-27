// Package hostdtest is an in-memory fake of the hostd API endpoints the
// provider uses, with failure injection for retries.
package hostdtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
)

// VM is one fake VM.
type VM struct {
	ID     int64
	Name   string
	Status string
	IP     string
}

// Server is the fake API.
type Server struct {
	*httptest.Server
	Project string

	mu          sync.Mutex
	next        int64
	VMs         map[int64]*VM
	ReservedIPs map[string]int64
	Creates     int
	// Failure injection, consumed in order.
	NoFreeIPv4 int // next N creates return 400 No free public IPv4
	RateLimit  int // next N requests return 429 Retry-After: 0
	// DropCreateReply makes the next successful create hang up without reply.
	DropCreateReply bool
	// KeepIPOnDelete simulates an address left reserved after delete.
	KeepIPOnDelete bool
	Requests       []string
}

// New starts a fake for project.
func New(project string) *Server {
	s := &Server{Project: project, next: 1000, VMs: map[int64]*VM{}, ReservedIPs: map[string]int64{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests = append(s.Requests, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if s.RateLimit > 0 {
		s.RateLimit--
		w.Header().Set("Retry-After", "0")
		http.Error(w, `{"detail":"rate limited"}`, http.StatusTooManyRequests)
		return
	}
	prefix := "/cloud/project/" + s.Project + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case rest == "public-ips/" && r.Method == http.MethodGet:
		var out []map[string]any
		for ip, vmid := range s.ReservedIPs {
			out = append(out, map[string]any{"ip": ip, "vmid": vmid, "status": "used"})
		}
		writeJSON(w, out)
	case rest == "vm/" && r.Method == http.MethodGet:
		out := []map[string]any{}
		for _, vm := range s.VMs {
			out = append(out, map[string]any{"vmid": vm.ID, "name": vm.Name, "status": vm.Status})
		}
		writeJSON(w, out)
	case rest == "vm/" && r.Method == http.MethodPost:
		var in struct {
			Hostname string `json:"hostname"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if s.NoFreeIPv4 > 0 {
			s.NoFreeIPv4--
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"wan_ip": "No free public IPv4 addresses available."}`))
			return
		}
		s.Creates++
		s.next++
		ip := fmt.Sprintf("38.56.199.%d", s.next%250+2)
		s.VMs[s.next] = &VM{ID: s.next, Name: in.Hostname, Status: "running", IP: ip}
		s.ReservedIPs[ip] = s.next
		if s.DropCreateReply {
			s.DropCreateReply = false
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"vmid": s.next})
	case len(parts) >= 2 && parts[0] == "vm":
		id, _ := strconv.ParseInt(parts[1], 10, 64)
		vm := s.VMs[id]
		if vm == nil {
			http.Error(w, `{"detail":"Not found."}`, http.StatusNotFound)
			return
		}
		sub := strings.Join(parts[2:], "/")
		switch {
		case sub == "" && r.Method == http.MethodGet:
			writeJSON(w, map[string]any{"vmid": vm.ID, "name": vm.Name, "status": vm.Status})
		case sub == "" && r.Method == http.MethodDelete:
			if vm.Status != "stopped" {
				http.Error(w, `{"detail":"VM must be stopped"}`, http.StatusBadRequest)
				return
			}
			delete(s.VMs, id)
			if r.URL.Query().Get("release_public_ip") == "true" && !s.KeepIPOnDelete {
				delete(s.ReservedIPs, vm.IP)
			}
			w.WriteHeader(http.StatusNoContent)
		case sub == "config/current" && r.Method == http.MethodGet:
			writeJSON(w, map[string]any{"name": vm.Name, "cores": 2, "ram_gb": 4, "wan": map[string]any{"ipv4": vm.IP}})
		case sub == "power/stop" && r.Method == http.MethodPost:
			vm.Status = "stopped"
			writeJSON(w, map[string]any{})
		case sub == "power/start" && r.Method == http.MethodPost:
			vm.Status = "running"
			writeJSON(w, map[string]any{})
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Count returns the VM count.
func (s *Server) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.VMs)
}
