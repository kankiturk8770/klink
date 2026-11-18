package link

// Helpers to read server address / stream info out of an arbitrary Xray
// outbound object (used for raw-JSON profiles).

func outboundServer(ob map[string]any) (string, int) {
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return "", 0
	}
	if vnext, ok := settings["vnext"].([]any); ok && len(vnext) > 0 {
		if m, ok := vnext[0].(map[string]any); ok {
			return strOf(m["address"]), asInt(m["port"], 0)
		}
	}
	if servers, ok := settings["servers"].([]any); ok && len(servers) > 0 {
		if m, ok := servers[0].(map[string]any); ok {
			return strOf(m["address"]), asInt(m["port"], 0)
		}
	}
	return "", 0
}

// setOutboundServer rewrites the server address/port inside an outbound object.
func setOutboundServer(ob map[string]any, host string, port int) {
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return
	}
	for _, key := range []string{"vnext", "servers"} {
		if arr, ok := settings[key].([]any); ok && len(arr) > 0 {
			if m, ok := arr[0].(map[string]any); ok {
				m["address"] = host
				m["port"] = port
			}
		}
	}
}

func outboundStreamInfo(ob map[string]any, realHost string) (sni, security, network string) {
	security, network = "none", "tcp"
	sni = realHost
	ss, _ := ob["streamSettings"].(map[string]any)
	if ss == nil {
		return
	}
	if n := strOf(ss["network"]); n != "" {
		network = n
	}
	if s := strOf(ss["security"]); s != "" {
		security = s
	}
	if tls, ok := ss["tlsSettings"].(map[string]any); ok {
		if n := strOf(tls["serverName"]); n != "" {
			sni = n
		}
	}
	if r, ok := ss["realitySettings"].(map[string]any); ok {
		if n := strOf(r["serverName"]); n != "" {
			sni = n
		}
	}
	return
}

// Rewrite returns a copy of the profile's outbound with the server address and
// port replaced (used to point Xray at the local spoof listener) and the tag set.
func (p *Profile) Rewrite(host string, port int, tag string) map[string]any {
	ob := cloneMap(p.outbound)
	setOutboundServer(ob, host, port)
	if tag != "" {
		ob["tag"] = tag
	}
	// Ensure TLS serverName is pinned to the real SNI even though we dial localhost.
	if ss, ok := ob["streamSettings"].(map[string]any); ok && p.SNI != "" {
		if tls, ok := ss["tlsSettings"].(map[string]any); ok {
			if strOf(tls["serverName"]) == "" {
				tls["serverName"] = p.SNI
			}
		}
	}
	return ob
}
