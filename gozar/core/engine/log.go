package engine

import (
	"fmt"
	"sync"
	"time"
)

// ringLog is a thread-safe bounded log buffer the UI can poll, plus an optional
// live callback for streaming lines.
type ringLog struct {
	mu    sync.Mutex
	lines []string
	max   int
	cb    func(string)
}

func newRingLog(max int) *ringLog {
	if max <= 0 {
		max = 500
	}
	return &ringLog{max: max}
}

func (r *ringLog) setCallback(cb func(string)) {
	r.mu.Lock()
	r.cb = cb
	r.mu.Unlock()
}

func (r *ringLog) addf(format string, args ...any) {
	r.add(fmt.Sprintf(format, args...))
}

func (r *ringLog) add(line string) {
	ts := time.Now().Format("15:04:05")
	entry := ts + " " + line
	r.mu.Lock()
	r.lines = append(r.lines, entry)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
	cb := r.cb
	r.mu.Unlock()
	if cb != nil {
		cb(entry)
	}
}

// Write implements io.Writer so a *log.Logger (spoof proxy, xray) can feed it.
func (r *ringLog) Write(p []byte) (int, error) {
	line := string(p)
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	if line != "" {
		r.add(line)
	}
	return len(p), nil
}

func (r *ringLog) dump() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := ""
	for _, l := range r.lines {
		out += l + "\n"
	}
	return out
}

func (r *ringLog) clear() {
	r.mu.Lock()
	r.lines = nil
	r.mu.Unlock()
}
