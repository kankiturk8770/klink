// Package mobile is the gomobile-bound surface for the Android app. It exposes
// a tiny, stable API over the engine: start/stop a tunnel, feed the VpnService
// TUN file descriptor to tun2socks, stream logs and stats, and run URL tests.
//
// All config crosses the boundary as a single JSON string (SettingsJSON) so the
// Kotlin side never has to mirror Go structs field-by-field.
package mobile

import (
	"encoding/json"
	"fmt"
	"sync"

	"gozar/core/engine"
	"gozar/core/link"
	t2s "gozar/core/tun"
)

var (
	mu      sync.Mutex
	eng     *engine.Engine
	tun     *t2s.Tunnel
	logCB   LogCallback
	protect VpnProtect
)

// LogCallback receives engine log lines on the Kotlin side.
type LogCallback interface{ OnLog(line string) }

// VpnProtect lets Go ask Android to protect a socket fd from the VPN
// (VpnService.protect). Return true on success.
type VpnProtect interface{ Protect(fd int) bool }

// SetLogCallback registers the Kotlin log sink. Pass nil to clear.
func SetLogCallback(cb LogCallback) {
	mu.Lock()
	defer mu.Unlock()
	logCB = cb
	if eng != nil {
		attachLog(eng, cb)
	}
}

// SetProtect registers the VpnService.protect bridge.
func SetProtect(p VpnProtect) {
	mu.Lock()
	defer mu.Unlock()
	protect = p
}

func attachLog(e *engine.Engine, cb LogCallback) {
	if cb == nil {
		e.SetLogCallback(nil)
		return
	}
	e.SetLogCallback(func(line string) { cb.OnLog(line) })
}

// ValidateLink parses a single share-link and returns a short description, or
// an error string. Useful for the "add profile" dialog before saving.
func ValidateLink(raw string) (string, error) {
	p, err := link.Parse(raw)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s · %s · %s:%d · %s", p.Remark, p.Protocol, p.RealHost, p.RealPort, p.Security), nil
}

// ProfilesJSON parses a subscription body (base64 or newline links) and returns
// a JSON array of {remark,protocol,host,port,security,link}.
func ProfilesJSON(subscription string) (string, error) {
	ps, err := link.ParseSubscription(subscription)
	if err != nil {
		return "", err
	}
	type row struct {
		Remark, Protocol, Host, Security, Link string
		Port                                   int
	}
	out := make([]row, 0, len(ps))
	for i, p := range ps {
		out = append(out, row{p.Remark, p.Protocol, p.RealHost, p.Security, splitLink(subscription, i), p.RealPort})
	}
	b, _ := json.Marshal(out)
	return string(b), nil
}

// splitLink is a best-effort recovery of the i-th raw link for the UI; for a
// base64 subscription we cannot cheaply recover individual lines, so callers
// that need the exact link should keep their own list. Returns "" when unknown.
func splitLink(_ string, _ int) string { return "" }

// Start brings the tunnel up. settingsJSON is engine.Settings; tunFd < 0 means
// "SOCKS only" (no TUN). mtu applies to the TUN device. Returns the local SOCKS
// port on success, or an error.
func Start(settingsJSON string, tunFd int, mtu int) (int, error) {
	mu.Lock()
	defer mu.Unlock()
	if eng != nil {
		return 0, fmt.Errorf("already running")
	}
	var s engine.Settings
	if err := json.Unmarshal([]byte(settingsJSON), &s); err != nil {
		return 0, fmt.Errorf("bad settings json: %w", err)
	}
	e := engine.New()
	attachLog(e, logCB)

	var protectFn func(fd uintptr)
	if protect != nil {
		p := protect
		protectFn = func(fd uintptr) { p.Protect(int(fd)) }
	}
	if err := e.Start(s, protectFn); err != nil {
		return 0, err
	}
	eng = e

	if tunFd >= 0 {
		tn, err := t2s.Start(tunFd, mtu, e.SocksPort(), protectFn, e.Logs)
		if err != nil {
			e.Stop()
			eng = nil
			return 0, fmt.Errorf("tun2socks: %w", err)
		}
		tun = tn
	}
	return e.SocksPort(), nil
}

// Stop tears everything down. Safe to call when already stopped.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if tun != nil {
		tun.Stop()
		tun = nil
	}
	if eng != nil {
		eng.Stop()
		eng = nil
	}
}

// IsRunning reports whether a tunnel is up.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return eng != nil && eng.State() == engine.StateRunning
}

// SocksPort returns the active SOCKS port, or 0.
func SocksPort() int {
	mu.Lock()
	defer mu.Unlock()
	if eng == nil {
		return 0
	}
	return eng.SocksPort()
}

// StatsJSON returns a JSON object of live counters.
func StatsJSON() string {
	mu.Lock()
	e := eng
	mu.Unlock()
	if e == nil {
		return `{"active":0,"total":0,"failed":0,"bytesUp":0,"bytesDn":0,"fakeSent":0,"lastErr":""}`
	}
	s := e.Snapshot()
	b, _ := json.Marshal(map[string]any{
		"active": s.Active, "total": s.Total, "failed": s.Failed,
		"bytesUp": s.BytesUp, "bytesDn": s.BytesDn, "fakeSent": s.FakeSent, "lastErr": s.LastErr,
	})
	return string(b)
}

// Logs returns the buffered log text.
func Logs() string {
	mu.Lock()
	e := eng
	mu.Unlock()
	if e == nil {
		return ""
	}
	return e.Logs()
}

// URLTest measures latency through the tunnel in milliseconds.
func URLTest(url string, timeoutMS int) (int64, error) {
	mu.Lock()
	e := eng
	mu.Unlock()
	if e == nil {
		return 0, fmt.Errorf("not running")
	}
	return e.URLTest(url, timeoutMS)
}
