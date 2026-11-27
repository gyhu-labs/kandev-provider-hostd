package hostd_test

import (
	"context"
	"testing"
	"time"

	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostd"
	"github.com/gyhu-labs/kandev-provider-hostd/internal/hostd/hostdtest"
)

func client(f *hostdtest.Server) *hostd.Client {
	c := hostd.New(f.URL, f.Project, "test-token")
	c.Sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	return c
}

func TestRetryAfterOn429(t *testing.T) {
	f := hostdtest.New("p")
	defer f.Close()
	f.RateLimit = 3
	if _, err := client(f).ListVMs(context.Background()); err != nil {
		t.Fatalf("429s must be retried: %v", err)
	}
}

func TestEnsureVMRetriesNoFreeIPv4(t *testing.T) {
	f := hostdtest.New("p")
	defer f.Close()
	f.NoFreeIPv4 = 2
	id, outcome, retries, err := client(f).EnsureVM(context.Background(), hostd.CreateVMInput{Hostname: "kd-a"}, time.Millisecond)
	if err != nil || outcome != hostd.OutcomeCreated || retries != 2 || id == 0 {
		t.Fatalf("got id=%d outcome=%s retries=%d err=%v", id, outcome, retries, err)
	}
	if f.Creates != 1 {
		t.Fatalf("exactly one VM must be created, got %d", f.Creates)
	}
}

func TestEnsureVMAdoptsExistingAndInterrupted(t *testing.T) {
	f := hostdtest.New("p")
	defer f.Close()
	c := client(f)
	first, _, _, err := c.EnsureVM(context.Background(), hostd.CreateVMInput{Hostname: "kd-b"}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	again, outcome, _, err := c.EnsureVM(context.Background(), hostd.CreateVMInput{Hostname: "kd-b"}, time.Millisecond)
	if err != nil || again != first || outcome != hostd.OutcomeAdopted || f.Creates != 1 {
		t.Fatalf("retry must adopt: %d %s %v creates=%d", again, outcome, err, f.Creates)
	}
	f.DropCreateReply = true
	lost, outcome, _, err := c.EnsureVM(context.Background(), hostd.CreateVMInput{Hostname: "kd-c"}, time.Millisecond)
	if err != nil || outcome != hostd.OutcomeAdopted || lost == 0 || f.Creates != 2 {
		t.Fatalf("lost reply must be resolved by listing: %d %s %v creates=%d", lost, outcome, err, f.Creates)
	}
}

func TestDestroyConfirmsOnlyOn404(t *testing.T) {
	f := hostdtest.New("p")
	defer f.Close()
	c := client(f)
	id, _, _, _ := c.EnsureVM(context.Background(), hostd.CreateVMInput{Hostname: "kd-d"}, time.Millisecond)
	ok, err := c.DestroyVM(context.Background(), id, "kd-d", time.Millisecond)
	if err != nil || !ok || f.Count() != 0 {
		t.Fatalf("destroy: ok=%v err=%v count=%d", ok, err, f.Count())
	}
	ips, _ := c.ListPublicIPs(context.Background())
	if len(ips) != 0 {
		t.Fatalf("IP must be released, got %v", ips)
	}
	ok, err = c.DestroyVM(context.Background(), id, "kd-d", time.Millisecond)
	if err != nil || !ok {
		t.Fatal("destroy of an absent VM must confirm absence")
	}
}

// TestDestroyNeverDeletesAReusedVMID: hostd reuses vmids, so a stale handle
// whose hostname no longer matches must report absence and leave the VM alone.
func TestDestroyNeverDeletesAReusedVMID(t *testing.T) {
	f := hostdtest.New("p")
	defer f.Close()
	c := client(f)
	id, _, _, _ := c.EnsureVM(context.Background(), hostd.CreateVMInput{Hostname: "kd-new-owner"}, time.Millisecond)
	ok, err := c.DestroyVM(context.Background(), id, "kd-old-owner", time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("stale handle must read as absent: ok=%v err=%v", ok, err)
	}
	if f.Count() != 1 {
		t.Fatal("the other environment's VM must survive")
	}
}
