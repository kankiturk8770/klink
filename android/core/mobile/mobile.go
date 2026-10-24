// Package mobile is the gomobile boundary for the Android VpnService.
package mobile

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kankipro/klink/android/core/client"
	tscore "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	StateDisconnected = client.StateDisconnected
	StateConnecting   = client.StateConnecting
	StateConnected    = client.StateConnected
	StateReconnecting = client.StateReconnecting
)

type engine struct {
	file     *os.File
	endpoint *iobased.Endpoint
	stack    *stack.Stack
	tunnel   *tunnel.Tunnel
	session  *client.Session
}

var global struct {
	sync.Mutex
	engine      *engine
	startCancel context.CancelFunc
}

var state atomic.Int32
var lastError atomic.Value
var currentNetwork atomic.Value

func init() {
	state.Store(StateDisconnected)
	lastError.Store("")
	currentNetwork.Store("")
}

// Start takes ownership of tunFD on every path, including failure. The Android
// service must use ParcelFileDescriptor.detachFd() before calling it.
func Start(tunFD int, subscriptionJSON string) error {
	global.Lock()
	if state.Load() != StateDisconnected {
		global.Unlock()
		return errors.New("VPN service is already running")
	}
	if tunFD < 0 {
		global.Unlock()
		return errors.New("invalid TUN file descriptor")
	}
	state.Store(StateConnecting)
	lastError.Store("")
	ctx, cancel := context.WithCancel(context.Background())
	global.startCancel = cancel
	global.Unlock()

	file := os.NewFile(uintptr(tunFD), "klink-android-tun")
	if file == nil {
		finishError(errors.New("could not open TUN descriptor"))
		cancel()
		return errors.New(LastError())
	}
	fail := func(err error) error {
		_ = file.Close()
		cancel()
		finishError(err)
		return errors.New(LastError())
	}
	connectCtx, connectCancel := context.WithTimeout(ctx, 30*time.Second)
	session, err := client.Connect(connectCtx, subscriptionJSON)
	connectCancel()
	if err != nil {
		return fail(err)
	}
	endpoint, err := iobased.New(file, 1500, 0)
	if err != nil {
		session.Close()
		return fail(err)
	}
	statistic.DefaultManager.ResetStatistic()
	tun := tunnel.New(&client.Proxy{Session: session}, statistic.DefaultManager)
	tun.ProcessAsync()
	netstack, err := tscore.CreateStack(&tscore.Config{LinkEndpoint: endpoint, TransportHandler: tun})
	if err != nil {
		tun.Close()
		endpoint.Close()
		session.Close()
		return fail(err)
	}
	eng := &engine{file: file, endpoint: endpoint, stack: netstack, tunnel: tun, session: session}
	global.Lock()
	if state.Load() == StateDisconnected {
		global.Unlock()
		stopEngine(eng)
		cancel()
		return errors.New("VPN was stopped while connecting")
	}
	global.engine = eng
	global.startCancel = nil
	global.Unlock()
	state.Store(StateConnected)
	currentNetwork.Store(session.Network())
	go watchSession(eng)
	return nil
}

func watchSession(eng *engine) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		global.Lock()
		active := global.engine == eng
		global.Unlock()
		if !active || eng.session.State() == client.StateDisconnected {
			return
		}
		currentNetwork.Store(eng.session.Network())
		if err := eng.session.LastError(); err != "" {
			lastError.Store(err)
		}
		switch eng.session.State() {
		case client.StateReconnecting:
			state.Store(StateReconnecting)
		case client.StateConnected:
			state.Store(StateConnected)
		}
	}
}

func finishError(err error) {
	if err == nil {
		err = errors.New("unknown error")
	}
	lastError.Store(err.Error())
	state.Store(StateDisconnected)
	global.Lock()
	global.startCancel = nil
	global.Unlock()
}

func stopEngine(eng *engine) {
	if eng == nil {
		return
	}
	eng.session.Close()
	_ = eng.file.Close()
	eng.endpoint.Close()
	eng.stack.Close()
	eng.stack.Wait()
	eng.tunnel.Close()
	eng.endpoint.Wait()
}

func Stop() {
	state.Store(StateDisconnected)
	currentNetwork.Store("")
	global.Lock()
	cancel := global.startCancel
	global.startCancel = nil
	eng := global.engine
	global.engine = nil
	global.Unlock()
	if cancel != nil {
		cancel()
	}
	stopEngine(eng)
}

func State() int { return int(state.Load()) }
func LastError() string {
	if value := lastError.Load(); value != nil {
		return value.(string)
	}
	return ""
}
func Network() string {
	if value := currentNetwork.Load(); value != nil {
		return value.(string)
	}
	return ""
}
func UploadBytes() int64   { return statistic.DefaultManager.Snapshot().UploadTotal }
func DownloadBytes() int64 { return statistic.DefaultManager.Snapshot().DownloadTotal }
func UploadSpeed() int64   { up, _ := statistic.DefaultManager.Now(); return up }
func DownloadSpeed() int64 { _, down := statistic.DefaultManager.Now(); return down }

func FetchSubscription(url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	return client.FetchSubscription(ctx, url)
}

func ValidateSubscription(json string) (string, error) {
	cfg, err := client.ParseSubscription([]byte(json))
	if err != nil {
		return "", err
	}
	return cfg.CanonicalJSON()
}

func Version() string { return "KLINK Android Core 1" }
