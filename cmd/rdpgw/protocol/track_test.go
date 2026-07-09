package protocol

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// resetConnections clears the global registry under its lock. Tests must
// not reassign the package-level Connections variable, since the lock
// protects the map's contents but not the variable's storage; concurrent
// goroutines from other tests can otherwise read a stale reference.
func resetConnections() {
	connectionsMu.Lock()
	clear(Connections)
	connectionsMu.Unlock()
}

// TestTunnelTrackerConcurrent hammers the global tunnel registry from many
// goroutines. The package's RegisterTunnel/RemoveTunnel write to a shared
// map, so the registry must serialize access. A concurrent write would be
// caught by the Go runtime as a fatal `concurrent map writes` (or by the
// race detector under -race).
func TestTunnelTrackerConcurrent(t *testing.T) {
	resetConnections()
	t.Cleanup(resetConnections)

	const goroutines = 200
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("tun-%d", i)
			RegisterTunnel(&Tunnel{Id: id}, &Processor{ctl: make(chan int)})
		}()
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("tun-%d", i)
			RemoveTunnel(&Tunnel{Id: id})
		}()
	}
	wg.Wait()
}

// TestRemoveTunnelFiresOnTunnelClosed verifies RemoveTunnel invokes
// OnTunnelClosed with the tunnel being removed, and that it's safe to
// leave OnTunnelClosed unset (the common case for anything that doesn't
// care, and the default in every other test in this file).
func TestRemoveTunnelFiresOnTunnelClosed(t *testing.T) {
	resetConnections()
	t.Cleanup(resetConnections)
	t.Cleanup(func() { OnTunnelClosed = nil })

	var got *Tunnel
	OnTunnelClosed = func(t *Tunnel) { got = t }

	tun := &Tunnel{Id: "tun-hook-test", PAATokenHash: "deadbeef"}
	RegisterTunnel(tun, &Processor{ctl: make(chan int)})
	RemoveTunnel(tun)

	if got != tun {
		t.Fatalf("OnTunnelClosed was not called with the removed tunnel")
	}
}

// TestRemoveTunnelWithoutHookDoesNotPanic verifies RemoveTunnel is safe to
// call when OnTunnelClosed is nil (its zero value).
func TestRemoveTunnelWithoutHookDoesNotPanic(t *testing.T) {
	resetConnections()
	t.Cleanup(resetConnections)
	OnTunnelClosed = nil

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("RemoveTunnel panicked with OnTunnelClosed unset: %v", r)
		}
	}()
	tun := &Tunnel{Id: "tun-no-hook"}
	RegisterTunnel(tun, &Processor{ctl: make(chan int)})
	RemoveTunnel(tun)
}

// TestTunnelLastSeenByHash verifies the still-open-tunnel lookup used for
// the rare case where a reconnect races an old tunnel that hasn't finished
// tearing down yet.
func TestTunnelLastSeenByHash(t *testing.T) {
	resetConnections()
	t.Cleanup(resetConnections)

	if _, found := TunnelLastSeenByHash("no-such-hash"); found {
		t.Error("TunnelLastSeenByHash found a match for a hash that was never registered")
	}
	if _, found := TunnelLastSeenByHash(""); found {
		t.Error("TunnelLastSeenByHash should never match on an empty hash")
	}

	seen := time.Now()
	tun := &Tunnel{Id: "tun-open", PAATokenHash: "abc123", LastSeen: seen}
	RegisterTunnel(tun, &Processor{ctl: make(chan int)})

	got, found := TunnelLastSeenByHash("abc123")
	if !found {
		t.Fatal("TunnelLastSeenByHash did not find a currently open tunnel by its token hash")
	}
	if !got.Equal(seen) {
		t.Errorf("TunnelLastSeenByHash returned %v, want %v", got, seen)
	}
}

// processor for a connection that exists in the registry.
func TestDisconnectKnownConnection(t *testing.T) {
	resetConnections()
	t.Cleanup(resetConnections)

	p := &Processor{ctl: make(chan int, 1)}
	connectionsMu.Lock()
	Connections["known"] = &Monitor{Processor: p}
	connectionsMu.Unlock()

	if err := Disconnect("known"); err != nil {
		t.Fatalf("Disconnect on known id returned err: %v", err)
	}
	select {
	case v := <-p.ctl:
		if v != ctlDisconnect {
			t.Errorf("ctl received %d, want ctlDisconnect=%d", v, ctlDisconnect)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Disconnect did not signal ctlDisconnect on the processor channel")
	}
}

// TestDisconnectMissingConnectionDoesNotPanic verifies that Disconnect on
// an id that is not in the registry returns an error rather than
// dereferencing a nil Monitor.
func TestDisconnectMissingConnectionDoesNotPanic(t *testing.T) {
	resetConnections()
	t.Cleanup(resetConnections)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Disconnect panicked on missing id: %v", r)
		}
	}()
	if err := Disconnect("nonexistent"); err == nil {
		t.Error("Disconnect on missing id returned no error")
	}
}
