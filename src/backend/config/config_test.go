package config

import (
	"testing"
	"time"

	"go.yaml.in/yaml/v2"
)

const upstreamsYAML = `app:
  dnsProxy:
    upstreams:
      - address: 8.8.8.8
        port: 53
      - address: 9.9.9.9
        port: 53
    health:
      enabled: true
      interval: 10s
      timeout: 2s
      failCycles: 3
      restoreCycles: 2
      restoreGap: 5m
`

func checkUpstreams(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg.App == nil || cfg.App.DNSProxy == nil {
		t.Fatalf("app/dnsProxy не распарсились")
	}
	ups := cfg.App.DNSProxy.Upstreams
	if ups == nil || len(*ups) != 2 {
		t.Fatalf("upstreams: %+v", ups)
	}
	if (*ups)[0].Address == nil || *(*ups)[0].Address != "8.8.8.8" || *(*ups)[0].Port != 53 {
		t.Fatalf("upstreams[0]: %+v", (*ups)[0])
	}
	h := cfg.App.DNSProxy.Health
	if h == nil || h.Enabled == nil || !*h.Enabled ||
		h.Interval == nil || *h.Interval != 10*time.Second ||
		h.Timeout == nil || *h.Timeout != 2*time.Second ||
		h.FailCycles == nil || *h.FailCycles != 3 ||
		h.RestoreCycles == nil || *h.RestoreCycles != 2 ||
		h.RestoreGap == nil || *h.RestoreGap != 5*time.Minute {
		t.Fatalf("health: %+v", h)
	}
}

// upstreams/health: yaml-теги читаются и переживают обратную запись
// (roundtrip без потерь - правила совместимости, GOTCHAS)
func TestDNSProxyUpstreamsYAMLRoundtrip(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(upstreamsYAML), &cfg); err != nil {
		t.Fatal(err)
	}
	checkUpstreams(t, &cfg)

	out, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	var cfg2 Config
	if err := yaml.Unmarshal(out, &cfg2); err != nil {
		t.Fatal(err)
	}
	checkUpstreams(t, &cfg2)
}
