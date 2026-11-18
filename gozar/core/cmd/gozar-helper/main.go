// Command gozar-helper is the root-mode packet-injection helper.
//
// On Android an unprivileged app process cannot open NFQUEUE / raw sockets
// (SELinux untrusted_app). When the user has root, the app drops this binary
// into its data dir and launches it as `su -c "gozar-helper"`, feeding a JSON
// request on stdin. The helper runs the SNI-spoofing proxy with the requested
// injector (active/passive/raw) bound to the physical interface + fwMark, prints
// the bound listen address as a JSON line, and keeps running until stdin closes
// (the app exits / revokes) or it receives SIGINT/SIGTERM.
//
// It also builds and runs on desktop Linux for testing: `sudo gozar-helper`.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gozar/core/config"
	"gozar/core/injection"
	"gozar/core/proxy"
)

// Request is the JSON the app writes to the helper's stdin.
type Request struct {
	ConnectIP     string `json:"connectIP"`
	ConnectPort   int    `json:"connectPort"`
	FakeSNI       string `json:"fakeSNI"`
	UTLS          string `json:"utls"`
	Mode          string `json:"mode"` // active, passive, raw
	ListenHost    string `json:"listenHost"`
	ListenPort    int    `json:"listenPort"`
	InterfaceName string `json:"interfaceName"`
	InterfaceIP   string `json:"interfaceIP"`
	FwMark        int    `json:"fwMark"`
	MTU           int    `json:"mtu"`

	FakeRepeat      int  `json:"fakeRepeat"`
	FakeDelayMS     int  `json:"fakeDelayMS"`
	AckTimeoutMS    int  `json:"ackTimeoutMS"`
	EnableFragment  bool `json:"enableFragment"`
	FragmentDelayMS int  `json:"fragmentDelayMS"`
	SNIChunk        int  `json:"sniChunk"`
}

// Response is the JSON line the helper prints on stdout once listening.
type Response struct {
	OK         bool   `json:"ok"`
	ListenAddr string `json:"listenAddr,omitempty"`
	Error      string `json:"error,omitempty"`
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	req, err := readRequest()
	if err != nil {
		emit(Response{OK: false, Error: "read request: " + err.Error()})
		os.Exit(2)
	}

	injector, err := parseMode(req.Mode)
	if err != nil {
		emit(Response{OK: false, Error: err.Error()})
		os.Exit(2)
	}

	cfg := &config.Config{
		ConnectIP:       req.ConnectIP,
		ConnectIPv4s:    []string{req.ConnectIP},
		ConnectPort:     req.ConnectPort,
		FakeSNI:         req.FakeSNI,
		UTLSClientHello: orStr(req.UTLS, "chrome"),
		ListenHost:      orStr(req.ListenHost, "127.0.0.1"),
		ListenPort:      req.ListenPort,
	}
	opts := proxy.Options{
		Injector:       injector,
		InterfaceName:  req.InterfaceName,
		LocalIP:        req.InterfaceIP,
		FwMark:         req.FwMark,
		MTU:            req.MTU,
		FakeRepeat:     orInt(req.FakeRepeat, 1),
		FakeDelay:      msOr(req.FakeDelayMS, 2),
		AckTimeout:     msOr(req.AckTimeoutMS, 2000),
		EnableFragment: req.EnableFragment,
		FragmentDelay:  msOr(req.FragmentDelayMS, 2),
		SNIChunk:       req.SNIChunk,
		ConnectTimeout: 10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Lifecycle: stop when stdin closes (parent death) or on a signal.
	go watchStdinEOF(cancel)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	ready := make(chan proxy.Ready, 1)
	runErr := make(chan error, 1)
	go func() { runErr <- proxy.Run(ctx, cfg, opts, ready) }()

	select {
	case r := <-ready:
		if r.Err != nil {
			emit(Response{OK: false, Error: r.Err.Error()})
			os.Exit(1)
		}
		emit(Response{OK: true, ListenAddr: r.ListenAddr})
	case err := <-runErr:
		emit(Response{OK: false, Error: errString(err)})
		os.Exit(1)
	case <-time.After(proxy.StartReadyTimeout):
		emit(Response{OK: false, Error: "start timeout"})
		os.Exit(1)
	}

	if err := <-runErr; err != nil && ctx.Err() == nil {
		log.Printf("helper: proxy stopped: %v", err)
		os.Exit(1)
	}
}

func readRequest() (*Request, error) {
	// Prefer argv[1] as a path/inline JSON for debugging; else read stdin.
	var data []byte
	var err error
	if len(os.Args) > 1 && os.Args[1] != "-" {
		if _, statErr := os.Stat(os.Args[1]); statErr == nil {
			data, err = os.ReadFile(os.Args[1])
		} else {
			data = []byte(os.Args[1])
		}
	} else {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	}
	if err != nil {
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	if req.ConnectIP == "" || req.ConnectPort == 0 {
		return nil, fmt.Errorf("connectIP and connectPort are required")
	}
	return &req, nil
}

// watchStdinEOF cancels when stdin reaches EOF. The app keeps the stdin pipe
// open for the helper's lifetime, so EOF means the app is gone.
func watchStdinEOF(cancel context.CancelFunc) {
	r := bufio.NewReader(os.Stdin)
	buf := make([]byte, 256)
	for {
		if _, err := r.Read(buf); err != nil {
			cancel()
			return
		}
	}
}

func parseMode(m string) (injection.InjectorMode, error) {
	switch m {
	case "", "active", "root-active":
		return injection.InjectorModeActive, nil
	case "passive", "root-passive":
		return injection.InjectorModePassive, nil
	case "raw", "root-raw":
		return injection.InjectorModeRaw, nil
	default:
		return "", fmt.Errorf("unknown mode %q (want active/passive/raw)", m)
	}
}

func emit(r Response) {
	b, _ := json.Marshal(r)
	fmt.Fprintln(os.Stdout, string(b))
	os.Stdout.Sync()
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
func msOr(v, def int) time.Duration {
	if v <= 0 {
		v = def
	}
	return time.Duration(v) * time.Millisecond
}
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
