//go:build linux

package injection

import "testing"

func TestRouteTableFromRouteGetAndroidTable(t *testing.T) {
	out := "104.19.230.21 via 192.168.1.1 dev wlan0 table 1026 src 192.168.1.20 uid 10257 cache"
	if got := routeTableFromRouteGet(out); got != "1026" {
		t.Fatalf("routeTableFromRouteGet() = %q, want 1026", got)
	}
}

func TestRouteTableFromRouteGetDefaultsToMain(t *testing.T) {
	out := "104.19.230.21 via 192.168.1.1 dev eth0 src 192.168.1.20"
	if got := routeTableFromRouteGet(out); got != "main" {
		t.Fatalf("routeTableFromRouteGet() = %q, want main", got)
	}
}
