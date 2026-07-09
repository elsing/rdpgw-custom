package protocol

import (
	"fmt"
	"sync"
	"time"
)

var (
	Connections   = map[string]*Monitor{}
	connectionsMu sync.RWMutex
)

// OnTunnelClosed, if set, is called by RemoveTunnel right before a tunnel
// is dropped from the registry, with that tunnel's final state (including
// LastSeen - the last time real data was read from the client). It exists
// so other packages can observe a tunnel's true last-activity time at the
// moment it closes, without protocol importing them - they already import
// protocol, so the reverse would be a cycle. This is the same
// dependency-injection pattern Gateway.CheckPAACookie / Gateway.CheckHost
// already use.
var OnTunnelClosed func(t *Tunnel)

type Monitor struct {
	Processor *Processor
	Tunnel    *Tunnel
}

const (
	ctlDisconnect = -1
)

func RegisterTunnel(t *Tunnel, p *Processor) {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()

	Connections[t.Id] = &Monitor{
		Processor: p,
		Tunnel:    t,
	}
}

func RemoveTunnel(t *Tunnel) {
	connectionsMu.Lock()
	delete(Connections, t.Id)
	connectionsMu.Unlock()

	if OnTunnelClosed != nil {
		OnTunnelClosed(t)
	}
}

// TunnelLastSeenByHash returns the LastSeen time of a currently still-open
// tunnel authenticated by the PAA token whose hash is given, if one
// exists. This covers the rare case where a reconnect attempt races an old
// tunnel that hasn't finished tearing down yet; the common case (the old
// tunnel already closed) is covered by OnTunnelClosed instead. This does a
// linear scan of currently open tunnels, which is fine at the connection
// counts a gateway like this typically handles, but is worth knowing about
// if that assumption changes.
func TunnelLastSeenByHash(hash string) (time.Time, bool) {
	if hash == "" {
		return time.Time{}, false
	}
	connectionsMu.RLock()
	defer connectionsMu.RUnlock()
	for _, m := range Connections {
		if m.Tunnel.PAATokenHash == hash {
			return m.Tunnel.LastSeen, true
		}
	}
	return time.Time{}, false
}

func Disconnect(id string) error {
	connectionsMu.RLock()
	m, ok := Connections[id]
	connectionsMu.RUnlock()

	if !ok {
		return fmt.Errorf("%s connection does not exist", id)
	}
	m.Processor.ctl <- ctlDisconnect
	return nil
}
