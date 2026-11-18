package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

// URLTest measures latency to testURL through the running SOCKS inbound.
// Returns milliseconds, or an error. The engine must be running.
func (e *Engine) URLTest(testURL string, timeoutMS int) (int64, error) {
	e.mu.Lock()
	port := e.socksPort
	running := e.state == StateRunning
	e.mu.Unlock()
	if !running || port == 0 {
		return 0, fmt.Errorf("engine not running")
	}
	if testURL == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return 0, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}

	start := time.Now()
	req, err := http.NewRequest(http.MethodGet, testURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	ms := time.Since(start).Milliseconds()
	if resp.StatusCode >= 400 {
		return ms, fmt.Errorf("http %d", resp.StatusCode)
	}
	return ms, nil
}
