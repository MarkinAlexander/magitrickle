package magitrickle

import (
	"errors"
	"testing"

	"magitrickle/app"
	"magitrickle/constant"
	"magitrickle/models"
)

// normalizeZones: канонизация зоны и апстримов, дедуп зон, кривой ввод ->
// ErrDnsZonesInvalid
func TestNormalizeZones(t *testing.T) {
	norm, err := normalizeZones([]models.AppConfigDNSProxyZone{
		{Zone: "  CORP.Example.COM. ", Upstreams: []models.AppConfigDNSProxyServer{
			{Address: "10.0.0.1"}, {Address: "10.0.0.1:53"},
		}},
		{Zone: "corp.example.com", Upstreams: []models.AppConfigDNSProxyServer{{Address: "tls://10.0.0.2"}}},
		{Zone: "other.net", Upstreams: []models.AppConfigDNSProxyServer{{Address: "https://10.0.0.3/dns-query"}}, FallbackOpen: true},
	})
	if err != nil {
		t.Fatalf("валидная таблица отвергнута: %v", err)
	}
	if len(norm) != 2 {
		t.Fatalf("дубль зоны должен схлопнуться, зон: %d", len(norm))
	}
	if norm[0].Zone != "corp.example.com" || norm[0].FallbackOpen {
		t.Fatalf("первая зона: %+v", norm[0])
	}
	if len(norm[0].Upstreams) != 1 || norm[0].Upstreams[0].Address != "10.0.0.1" || norm[0].Upstreams[0].Port != 53 {
		t.Fatalf("апстримы зоны не канонизированы: %+v", norm[0].Upstreams)
	}
	if norm[1].Upstreams[0].Address != "https://10.0.0.3:443/dns-query" || !norm[1].FallbackOpen {
		t.Fatalf("вторая зона: %+v", norm[1])
	}

	for i, bad := range []models.AppConfigDNSProxyZone{
		{Zone: "", Upstreams: []models.AppConfigDNSProxyServer{{Address: "10.0.0.1"}}},
		{Zone: "a..b", Upstreams: []models.AppConfigDNSProxyServer{{Address: "10.0.0.1"}}},
		{Zone: "ok.net", Upstreams: nil},
		{Zone: "ok.net", Upstreams: []models.AppConfigDNSProxyServer{{Address: "quic://10.0.0.1"}}},
	} {
		if _, err := normalizeZones([]models.AppConfigDNSProxyZone{bad}); !errors.Is(err, app.ErrDnsZonesInvalid) {
			t.Fatalf("таблица[%d] должна отвергаться c ErrDnsZonesInvalid, got %v", i, err)
		}
	}
}

// SetDnsZones на «холодном» App (dnsMITM == nil): валидация до записи,
// пустой список = легальная очистка, общий каскад не тронут
func TestSetDnsZonesModel(t *testing.T) {
	a := &App{config: constant.DefaultAppConfig}

	if err := a.SetDnsZones([]models.AppConfigDNSProxyZone{{Zone: "bad..zone"}}); !errors.Is(err, app.ErrDnsZonesInvalid) {
		t.Fatalf("кривая зона должна отвергаться: %v", err)
	}
	if a.config.DNSProxy.Zones != nil {
		t.Fatalf("после отказа таблица не должна меняться: %+v", a.config.DNSProxy.Zones)
	}

	if err := a.SetDnsZones(nil); err != nil {
		t.Fatalf("пустой список = очистка, не ошибка: %v", err)
	}
	if a.config.DNSProxy.Zones == nil || len(a.config.DNSProxy.Zones) != 0 {
		t.Fatalf("после очистки таблица должна быть пустой (не nil-ключ): %+v", a.config.DNSProxy.Zones)
	}

	a.config.DNSProxy.Zones = []models.AppConfigDNSProxyZone{{Zone: "corp.example.com",
		Upstreams: []models.AppConfigDNSProxyServer{{Address: "10.0.0.1", Port: 53}}}}
	if _, ok := a.DnsZonesSnapshot(); ok {
		t.Fatalf("до Start снапшот должен быть недоступен (dnsMITM == nil)")
	}
	if len(a.config.DNSProxy.Upstreams) != 0 || a.config.DNSProxy.Upstream.Address != constant.DefaultAppConfig.DNSProxy.Upstream.Address {
		t.Fatalf("общий каскад затронут: %+v", a.config.DNSProxy.Upstream)
	}
}

// персистентность: таблица зон доезжает до yaml-модели файла; nil не
// записывается (ключ не появляется), пустой список - пустой ключ
func TestZonesToFile(t *testing.T) {
	if zonesToFile(nil) != nil {
		t.Fatalf("nil должен сохраняться как nil")
	}
	f := zonesToFile([]models.AppConfigDNSProxyZone{{
		Zone:         "corp.example.com",
		Upstreams:    []models.AppConfigDNSProxyServer{{Address: "10.0.0.1", Port: 53}},
		FallbackOpen: true,
	}})
	if f == nil || len(*f) != 1 {
		t.Fatalf("таблица потеряна: %+v", f)
	}
	z := (*f)[0]
	if z.Zone == nil || *z.Zone != "corp.example.com" || z.Fallback == nil || !*z.Fallback {
		t.Fatalf("поля зоны: %+v", z)
	}
	if z.Upstreams == nil || len(*z.Upstreams) != 1 || *(*z.Upstreams)[0].Address != "10.0.0.1" || *(*z.Upstreams)[0].Port != 53 {
		t.Fatalf("апстримы зоны: %+v", z.Upstreams)
	}
	empty := zonesToFile([]models.AppConfigDNSProxyZone{})
	if empty == nil || len(*empty) != 0 {
		t.Fatalf("пустой список должен записываться пустым ключом: %+v", empty)
	}
}

// dnsZoneRoutes: модель -> маршруты прокси (схемы как есть, plain ->
// host:port)
func TestDnsZoneRoutes(t *testing.T) {
	if dnsZoneRoutes(models.AppConfigDNSProxy{}) != nil {
		t.Fatalf("пустая таблица должна давать nil")
	}
	routes := dnsZoneRoutes(models.AppConfigDNSProxy{Zones: []models.AppConfigDNSProxyZone{
		{Zone: "corp.example.com", Upstreams: []models.AppConfigDNSProxyServer{
			{Address: "10.0.0.1", Port: 5353},
			{Address: "tls://10.0.0.2:853", Port: 853},
		}, FallbackOpen: true},
		{Zone: "", Upstreams: []models.AppConfigDNSProxyServer{{Address: "10.0.0.9"}}}, // выкинута
	}})
	if len(routes) != 1 {
		t.Fatalf("маршрутов: %d", len(routes))
	}
	if routes[0].Zone != "corp.example.com" || !routes[0].FallbackOpen {
		t.Fatalf("маршрут: %+v", routes[0])
	}
	if len(routes[0].UpstreamAddrs) != 2 || routes[0].UpstreamAddrs[0] != "10.0.0.1:5353" || routes[0].UpstreamAddrs[1] != "tls://10.0.0.2:853" {
		t.Fatalf("адреса маршрута: %+v", routes[0].UpstreamAddrs)
	}
}
