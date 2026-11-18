package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	xcore "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all" // register all protocols/transports

	"gozar/core/config"
	"gozar/core/injection"
	"gozar/core/link"
	"gozar/core/proxy"
)

// State is the engine lifecycle state.
type State int32

const (
	StateStopped State = iota
	StateStarting
	StateRunning
	StateError
)

func (s State) String() string {
	switch s {
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateError:
		return "error"
	default:
		return "stopped"
	}
}

// Engine orchestrates the spoof proxy + Xray instance. It is safe for one
// active tunnel at a time; call Stop before Start again.
type Engine struct {
	mu        sync.Mutex
	state     State
	cancel    context.CancelFunc
	instance  *xcore.Instance
	stats     *proxy.Stats
	logs      *ringLog
	active    *link.Profile
	socksPort int
	spoofPort int
	lastErr   string
}

// New creates an idle engine.
func New() *Engine {
	return &Engine{logs: newRingLog(1000), stats: &proxy.Stats{}}
}

// SetLogCallback streams each new log line to cb (may be nil).
func (e *Engine) SetLogCallback(cb func(string)) { e.logs.setCallback(cb) }

// Logs returns the buffered log text.
func (e *Engine) Logs() string { return e.logs.dump() }

// ClearLogs empties the log buffer.
func (e *Engine) ClearLogs() { e.logs.clear() }

// SocksPort returns the local SOCKS inbound port (0 until running).
func (e *Engine) SocksPort() int { e.mu.Lock(); defer e.mu.Unlock(); return e.socksPort }

// State returns the current lifecycle state.
func (e *Engine) State() State { e.mu.Lock(); defer e.mu.Unlock(); return e.state }

// Stat snapshot for the UI.
type Stat struct {
	Active   int64
	Total    int64
	Failed   int64
	BytesUp  int64
	BytesDn  int64
	FakeSent int64
	LastErr  string
}

// Snapshot returns the live counters.
func (e *Engine) Snapshot() Stat {
	st := e.stats
	lastErr, _ := st.LastErr.Load().(string)
	if lastErr == "" {
		e.mu.Lock()
		lastErr = e.lastErr
		e.mu.Unlock()
	}
	return Stat{
		Active: st.Active.Load(), Total: st.Total.Load(), Failed: st.Failed.Load(),
		BytesUp: st.BytesUp.Load(), BytesDn: st.BytesDn.Load(),
		FakeSent: st.FakeSent.Load(), LastErr: lastErr,
	}
}

func (e *Engine) setState(s State, errMsg string) {
	e.mu.Lock()
	e.state = s
	if errMsg != "" {
		e.lastErr = errMsg
	}
	e.mu.Unlock()
}

// Start brings up the tunnel from the given settings and optional protect hook.
// protect is called for every upstream socket (Android VpnService.protect).
// It returns once Xray and the spoof proxy are listening, or an error.
func (e *Engine) Start(s Settings, protect func(fd uintptr)) error {
	e.mu.Lock()
	if e.state == StateRunning || e.state == StateStarting {
		e.mu.Unlock()
		return fmt.Errorf("engine already running")
	}
	e.state = StateStarting
	e.stats = &proxy.Stats{}
	e.mu.Unlock()

	if len(s.Links) == 0 {
		e.setState(StateError, "no links")
		return fmt.Errorf("no links provided")
	}
	active, err := link.Parse(s.Links[0])
	if err != nil {
		e.setState(StateError, err.Error())
		return fmt.Errorf("parse active link: %w", err)
	}
	e.active = active
	e.logs.addf("profile: %s %s %s:%d sni=%s net=%s sec=%s",
		active.Remark, active.Protocol, active.RealHost, active.RealPort, active.SNI, active.Network, active.Security)

	ctx, cancel := context.WithCancel(context.Background())

	// Resolve the real server to an IPv4 for the spoof proxy.
	connectIP, err := resolveIPv4(ctx, active.RealHost, protect)
	if err != nil {
		cancel()
		e.setState(StateError, err.Error())
		return fmt.Errorf("resolve %s: %w", active.RealHost, err)
	}
	e.logs.addf("resolved %s -> %s", active.RealHost, connectIP)

	// Choose ports.
	socksPort := s.SocksPort
	if socksPort == 0 {
		socksPort, err = freePort()
		if err != nil {
			cancel()
			e.setState(StateError, err.Error())
			return err
		}
	}

	dialHost, dialPort := active.RealHost, active.RealPort

	// Start the spoof proxy (if enabled) and point Xray at it.
	if s.Spoof.Enabled {
		spoofPort, err := freePort()
		if err != nil {
			cancel()
			e.setState(StateError, err.Error())
			return err
		}
		spoofCfg, opts, err := e.buildSpoof(connectIP, active, s, protect)
		if err != nil {
			cancel()
			e.setState(StateError, err.Error())
			return err
		}
		spoofCfg.ListenHost = "127.0.0.1"
		spoofCfg.ListenPort = spoofPort
		ready := make(chan proxy.Ready, 1)
		go func() {
			if rerr := proxy.Run(ctx, spoofCfg, opts, ready); rerr != nil {
				e.logs.addf("spoof: stopped: %v", rerr)
			}
		}()
		select {
		case r := <-ready:
			if r.Err != nil {
				cancel()
				e.setState(StateError, r.Err.Error())
				return fmt.Errorf("spoof start: %w", r.Err)
			}
			_, lp, _ := net.SplitHostPort(r.ListenAddr)
			dialPort, _ = strconv.Atoi(lp)
		case <-time.After(proxy.StartReadyTimeout):
			cancel()
			e.setState(StateError, "spoof start timeout")
			return fmt.Errorf("spoof start timeout")
		}
		dialHost = "127.0.0.1"
		e.spoofPort = dialPort
		e.logs.addf("spoof: listening on 127.0.0.1:%d -> %s:%d (fake SNI %s, mode %s)",
			dialPort, connectIP, active.RealPort, spoofCfg.FakeSNI, s.Spoof.Mode)
	} else {
		e.logs.add("spoof: disabled (direct dial)")
	}

	// Build and start Xray.
	cfgBytes, err := buildXrayConfig(active, dialHost, dialPort, socksPort, s)
	if err != nil {
		cancel()
		e.setState(StateError, err.Error())
		return err
	}
	inst, err := xcore.StartInstance("json", cfgBytes)
	if err != nil {
		cancel()
		e.setState(StateError, err.Error())
		return fmt.Errorf("xray start: %w", err)
	}

	e.mu.Lock()
	e.cancel = cancel
	e.instance = inst
	e.socksPort = socksPort
	e.state = StateRunning
	e.mu.Unlock()
	e.logs.addf("xray: started, SOCKS inbound 127.0.0.1:%d", socksPort)
	return nil
}

// Stop tears down Xray and the spoof proxy.
func (e *Engine) Stop() {
	e.mu.Lock()
	cancel := e.cancel
	inst := e.instance
	e.cancel = nil
	e.instance = nil
	e.state = StateStopped
	e.mu.Unlock()
	if inst != nil {
		_ = inst.Close()
	}
	if cancel != nil {
		cancel()
	}
	e.logs.add("engine: stopped")
}

func (e *Engine) buildSpoof(connectIP string, active *link.Profile, s Settings, protect func(fd uintptr)) (*config.Config, proxy.Options, error) {
	sp := s.Spoof
	fakeSNI := sp.FakeSNI
	if strings.TrimSpace(fakeSNI) == "" {
		fakeSNI = deriveFakeSNI(active.SNI, active.RealHost)
	}
	cfg := &config.Config{
		ConnectIP:       connectIP,
		ConnectIPv4s:    []string{connectIP},
		ConnectPort:     active.RealPort,
		FakeSNI:         fakeSNI,
		UTLSClientHello: firstNonEmptyStr(sp.UTLS, "chrome"),
	}
	opts := proxy.Options{
		FakeRepeat:     maxInt(sp.FakeRepeat, 1),
		FakeDelay:      ms(sp.FakeDelayMS, 2),
		AckTimeout:     ms(sp.AckTimeoutMS, 2000),
		EnableFragment: sp.EnableFragment,
		FragmentDelay:  ms(sp.FragmentDelayMS, 2),
		SNIChunk:       sp.SNIChunk,
		TLSRecordSplit: sp.TLSRecordSplit,
		Disorder:       sp.Disorder,
		DisorderTTL:    sp.DisorderTTL,
		OOB:            sp.OOB,
		ConnectTimeout: ms(sp.ConnectTimeoutMS, 10000),
		Control:        protect,
		Logger:         log.New(e.logs, "", 0),
		Stats:          e.stats,
	}
	switch sp.Mode {
	case "root-active", "":
		opts.Injector = injection.InjectorModeActive
	case "root-passive":
		opts.Injector = injection.InjectorModePassive
	case "root-raw":
		opts.Injector = injection.InjectorModeRaw
	case "non-root":
		opts.Injector = proxy.InjectorNone
		opts.FakeTTL = sp.FakeTTL
		opts.FakeHold = ms(sp.FakeHoldMS, 5)
	default:
		return nil, proxy.Options{}, fmt.Errorf("unknown spoof mode %q", sp.Mode)
	}
	return cfg, opts, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ms(v, def int) time.Duration {
	if v <= 0 {
		return time.Duration(def) * time.Millisecond
	}
	return time.Duration(v) * time.Millisecond
}
