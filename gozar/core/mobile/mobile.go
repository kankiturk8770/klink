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
	"strings"
	"sync"
	"time"

	"gozar/core/engine"
	"gozar/core/link"
	t2s "gozar/core/tun"
)

// appLog keeps app-side lines and the last engine run's log, so the Logs tab is
// never empty after a failed start (the failed engine used to be discarded with
// its whole buffer).
var (
	appLogMu sync.Mutex
	appLog   []string
)

const appLogMax = 600

func addAppLog(line string) {
	appLogMu.Lock()
	defer appLogMu.Unlock()
	appLog = append(appLog, time.Now().Format("15:04:05")+" "+line)
	if len(appLog) > appLogMax {
		appLog = appLog[len(appLog)-appLogMax:]
	}
}

// keepEngineLog copies a finished/failed engine's buffer into appLog.
func keepEngineLog(text string) {
	if text == "" {
		return
	}
	appLogMu.Lock()
	defer appLogMu.Unlock()
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if l != "" {
			appLog = append(appLog, l)
		}
	}
	if len(appLog) > appLogMax {
		appLog = appLog[len(appLog)-appLogMax:]
	}
}

func appLogText() string {
	appLogMu.Lock()
	defer appLogMu.Unlock()
	if len(appLog) == 0 {
		return ""
	}
	return strings.Join(appLog, "\n") + "\n"
}

// AppendLog lets the Android side write into the same log the UI shows.
func AppendLog(line string) { addAppLog(line) }

// ClearLogs empties the app log.
func ClearLogs() {
	appLogMu.Lock()
	appLog = nil
	appLogMu.Unlock()
}

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
		keepEngineLog(e.Logs())
		addAppLog("start failed: " + err.Error())
		return 0, err
	}
	eng = e

	if tunFd >= 0 {
		tn, err := t2s.Start(tunFd, mtu, e.SocksPort(), e.DNSPort(), protectFn, e.Logs)
		if err != nil {
			e.Stop()
			keepEngineLog(e.Logs())
			addAppLog("ERROR: tun2socks: " + err.Error())
			eng = nil
			return 0, fmt.Errorf("tun2socks: %w", err)
		}
		tun = tn
		e.Logf("tun2socks: TUN fd attached (mtu %d), DNS -> FakeDNS 127.0.0.1:%d", mtu, e.DNSPort())
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
		keepEngineLog(eng.Logs())
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

// Logs returns the app log (previous runs, app-side lines, failures) followed by
// the running engine's live log.
func Logs() string {
	mu.Lock()
	e := eng
	mu.Unlock()
	out := appLogText()
	if e != nil {
		out += e.Logs()
	}
	return out
}

// ProfileInfoJSON parses a link WITHOUT any network access and returns
// {"remark","protocol","host","port","sni","network","security"}.
func ProfileInfoJSON(rawLink string) (string, error) {
	p, err := link.Parse(rawLink)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(map[string]any{
		"remark": p.Remark, "protocol": p.Protocol, "host": p.RealHost, "port": p.RealPort,
		"sni": p.SNI, "network": p.Network, "security": p.Security,
	})
	return string(b), nil
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

// ServerInfoJSON returns {"host","ip","port","sni","protocol","fakeSNI"} for the
// first link, resolving the server to an IPv4. Used by the root-helper flow.
func ServerInfoJSON(rawLink string) (string, error) {
	p, err := link.Parse(rawLink)
	if err != nil {
		return "", err
	}
	var protectFn func(fd uintptr)
	mu.Lock()
	pr := protect
	mu.Unlock()
	if pr != nil {
		protectFn = func(fd uintptr) { pr.Protect(int(fd)) }
	}
	ip, err := engine.ResolveServerIPv4(p.RealHost, protectFn)
	if err != nil {
		return "", err
	}
	out := map[string]any{
		"host": p.RealHost, "ip": ip, "port": p.RealPort,
		"sni": p.SNI, "protocol": p.Protocol,
		"fakeSNI": engine.DeriveFakeSNI(p.SNI, p.RealHost),
	}
	b, _ := json.Marshal(out)
	return string(b), nil
}
