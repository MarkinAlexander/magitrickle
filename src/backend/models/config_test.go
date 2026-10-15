package models

import "testing"

// UpstreamList: непустой список вытесняет одиночный legacy-upstream,
// пустой - откат на legacy (обратная совместимость, 43-док §5)
func TestUpstreamListResolution(t *testing.T) {
	c := AppConfigDNSProxy{Upstream: AppConfigDNSProxyServer{Address: "127.0.0.1", Port: 53}}
	l := c.UpstreamList()
	if len(l) != 1 || l[0].Address != "127.0.0.1" || l[0].Port != 53 {
		t.Fatalf("legacy: %+v", l)
	}
	c.Upstreams = []AppConfigDNSProxyServer{{Address: "8.8.8.8", Port: 53}, {Address: "9.9.9.9", Port: 53}}
	l = c.UpstreamList()
	if len(l) != 2 || l[0].Address != "8.8.8.8" || l[1].Address != "9.9.9.9" {
		t.Fatalf("список: %+v", l)
	}
}
