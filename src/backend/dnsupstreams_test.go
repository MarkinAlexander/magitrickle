package magitrickle

import (
	"errors"
	"testing"
	"time"

	"magitrickle/app"
	"magitrickle/constant"
	"magitrickle/models"
)

// parseUpstreamAddrs: порт по умолчанию 53, явный порт, скобки ipv6,
// дедуп; пустой/кривой список -> app.ErrDnsUpstreamsInvalid
func TestParseUpstreamAddrs(t *testing.T) {
	ups, err := parseUpstreamAddrs([]string{"8.8.8.8", "77.88.8.8:5353", "8.8.8.8:53", "  ", "[::1]:5353"})
	if err != nil {
		t.Fatalf("валидный список отвергнут: %v", err)
	}
	if len(ups) != 3 {
		t.Fatalf("ожидались 3 уникальных (дубль и пустой схлопнуты): %+v", ups)
	}
	if ups[0].Address != "8.8.8.8" || ups[0].Port != 53 {
		t.Fatalf("порт по умолчанию: %+v", ups[0])
	}
	if ups[1].Port != 5353 {
		t.Fatalf("явный порт: %+v", ups[1])
	}
	if ups[2].Address != "::1" || ups[2].Port != 5353 {
		t.Fatalf("ipv6 в скобках: %+v", ups[2])
	}

	for _, bad := range [][]string{
		nil,
		{},
		{""},
		{"  "},
		{"8.8.8.8:0"},
		{"8.8.8.8:99999"},
		{"8.8.8.8:dns"},
		{":53"},
	} {
		if _, err := parseUpstreamAddrs(bad); !errors.Is(err, app.ErrDnsUpstreamsInvalid) {
			t.Fatalf("список %v должен быть отвергнут c ErrDnsUpstreamsInvalid, got %v", bad, err)
		}
	}
}

// SetDnsUpstreams на «холодном» App (dnsMITM == nil): кривой список
// отвергается ДО записи; после записи модель несёт новый список, а legacy
// Upstream не тронут (остаётся фолбэком)
func TestSetDnsUpstreamsModel(t *testing.T) {
	a := &App{config: constant.DefaultAppConfig}

	if err := a.SetDnsUpstreams([]string{}, nil); !errors.Is(err, app.ErrDnsUpstreamsInvalid) {
		t.Fatalf("пустой список должен отвергаться: %v", err)
	}
	if a.config.DNSProxy.Upstreams != nil {
		t.Fatalf("после отказа список не должен меняться: %+v", a.config.DNSProxy.Upstreams)
	}

	// валидный список ложится в модель (без записи файла - SaveConfig не
	// вызываем: AppStateDir вне репозитория; персистентность - в
	// TestUpstreamsToFile ниже); dnsMITM nil - не падаем
	ups, err := parseUpstreamAddrs([]string{"8.8.8.8", "77.88.8.8:53"})
	if err != nil {
		t.Fatal(err)
	}
	a.config.DNSProxy.Upstreams = ups
	list := a.config.DNSProxy.UpstreamList()
	if len(list) != 2 || list[0].Address != "8.8.8.8" || list[1].Address != "77.88.8.8" {
		t.Fatalf("UpstreamList не подхватил список: %+v", list)
	}
	if a.config.DNSProxy.Upstream.Address != constant.DefaultAppConfig.DNSProxy.Upstream.Address {
		t.Fatalf("legacy Upstream затёрт: %+v", a.config.DNSProxy.Upstream)
	}
	if _, ok := a.DnsUpstreamsSnapshot(); ok {
		t.Fatalf("до Start снапшот должен быть недоступен (dnsMITM == nil)")
	}
}

// персистентность: список из редактора доезжает до yaml-модели файла
// (upstreamsToFile), nil остаётся nil - ключ в файле не появляется
func TestUpstreamsToFile(t *testing.T) {
	ups, err := parseUpstreamAddrs([]string{"8.8.8.8", "77.88.8.8:5353"})
	if err != nil {
		t.Fatal(err)
	}
	f := upstreamsToFile(ups)
	if f == nil || len(*f) != 2 {
		t.Fatalf("список потерян: %+v", f)
	}
	if (*f)[0].Address == nil || *(*f)[0].Address != "8.8.8.8" || *(*f)[0].Port != 53 {
		t.Fatalf("первый апстрим: %+v", (*f)[0])
	}
	if (*f)[1].Address == nil || *(*f)[1].Address != "77.88.8.8" || *(*f)[1].Port != 5353 {
		t.Fatalf("второй апстрим: %+v", (*f)[1])
	}
	if upstreamsToFile(nil) != nil {
		t.Fatalf("nil должен сохраняться как nil (ключ не появляется)")
	}
}

// схемы DoT/DoH: канонический URI в Address (порт/путь внутри), порт
// дублируется в Port, дедуп по канонической строке; кривые схемы отвергаются
func TestParseUpstreamAddrsSchemes(t *testing.T) {
	ups, err := parseUpstreamAddrs([]string{
		"tls://1.1.1.1",
		"tls://dns.google:853",
		"tls://1.1.1.1:853", // дубль первого (умолчание порта)
		"https://dns.google",
		"https://1.1.1.1/dns-query",
		"https://dns.google/dns-query", // дубль (умолчания порт+путь)
	})
	if err != nil {
		t.Fatalf("валидный список отвергнут: %v", err)
	}
	if len(ups) != 4 {
		t.Fatalf("ожидались 4 уникальных: %+v", ups)
	}
	if ups[0].Address != "tls://1.1.1.1:853" || ups[0].Port != 853 {
		t.Fatalf("DoT по умолчанию: %+v", ups[0])
	}
	if ups[1].Address != "tls://dns.google:853" {
		t.Fatalf("DoT имя: %+v", ups[1])
	}
	if ups[2].Address != "https://dns.google:443/dns-query" || ups[2].Port != 443 {
		t.Fatalf("DoH по умолчанию: %+v", ups[2])
	}
	if ups[3].Address != "https://1.1.1.1:443/dns-query" {
		t.Fatalf("DoH с IP: %+v", ups[3])
	}

	for _, bad := range [][]string{
		{"tls://"},
		{"https://"},
		{"http://dns.google"},
		{"quic://dns.google"},
		{"tls://1.1.1.1/path"},
		{"tls://1.1.1.1:0"},
		{"https://dns.google:0/dns-query"},
	} {
		if _, err := parseUpstreamAddrs(bad); !errors.Is(err, app.ErrDnsUpstreamsInvalid) {
			t.Fatalf("список %v должен быть отвергнут, got %v", bad, err)
		}
	}
}

// dnsUpstreamAddrs: схемы проходят в прокси как есть, plain собирается в
// host:port - модель с URI живёт в конфиге без потерь
func TestDnsUpstreamAddrsSchemes(t *testing.T) {
	c := models.AppConfigDNSProxy{Upstreams: []models.AppConfigDNSProxyServer{
		{Address: "tls://1.1.1.1:853", Port: 853},
		{Address: "https://dns.google:443/dns-query", Port: 443},
		{Address: "8.8.8.8", Port: 53},
	}}
	got := dnsUpstreamAddrs(c)
	want := []string{"tls://1.1.1.1:853", "https://dns.google:443/dns-query", "8.8.8.8:53"}
	if len(got) != len(want) {
		t.Fatalf("адреса: %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("адрес[%d] = %q, хочу %q", i, got[i], want[i])
		}
	}
}

// rev14: health-патч в SetDnsUpstreams - nil addrs = список не трогать,
// nil-поля патча = поле не трогать, диапазоны валидируются ДО записи
func TestSetDnsUpstreamsHealthPatch(t *testing.T) {
	a := &App{config: constant.DefaultAppConfig}
	def := constant.DefaultAppConfig.DNSProxy.Health

	ups, err := parseUpstreamAddrs([]string{"8.8.8.8", "77.88.8.8:53"})
	if err != nil {
		t.Fatal(err)
	}
	a.config.DNSProxy.Upstreams = ups

	// nil addrs + nil health - честный no-op
	if err := a.SetDnsUpstreams(nil, nil); err != nil {
		t.Fatalf("no-op должен проходить: %v", err)
	}
	if len(a.config.DNSProxy.UpstreamList()) != 2 {
		t.Fatalf("список потерян при no-op: %+v", a.config.DNSProxy.UpstreamList())
	}

	// частичный патч: интервал и enabled меняются, остальное - дефолт
	i10 := uint(10)
	on := true
	f5 := uint(5)
	if err := a.SetDnsUpstreams(nil, &models.AppConfigDNSProxyHealthPatch{
		Enabled: &on, IntervalSec: &i10, FailCycles: &f5,
	}); err != nil {
		t.Fatalf("частичный патч отвергнут: %v", err)
	}
	h := a.config.DNSProxy.Health
	if !h.Enabled || h.Interval != 10*time.Second || h.FailCycles != 5 {
		t.Fatalf("частичный патч не лёг: %+v", h)
	}
	if h.Timeout != def.Timeout || h.RestoreCycles != def.RestoreCycles || h.RestoreGap != def.RestoreGap {
		t.Fatalf("nil-поля патча трогать нельзя: %+v (дефолт %+v)", h, def)
	}

	// здоровье-конверсии: секунды -> длительности
	gap0 := uint(0)
	t3 := uint(3)
	if err := a.SetDnsUpstreams(nil, &models.AppConfigDNSProxyHealthPatch{
		TimeoutSec: &t3, RestoreGapSec: &gap0,
	}); err != nil {
		t.Fatalf("патч паузы 0 отвергнут: %v", err)
	}
	h = a.config.DNSProxy.Health
	if h.Timeout != 3*time.Second || h.RestoreGap != 0 {
		t.Fatalf("конверсия секунд: %+v", h)
	}

	// диапазоны: всё вне - ErrDnsUpstreamsInvalid и модель не тронута
	bad := []models.AppConfigDNSProxyHealthPatch{
		{IntervalSec: ptrU(4)}, {IntervalSec: ptrU(301)},
		{TimeoutSec: ptrU(0)}, {TimeoutSec: ptrU(11)},
		{FailCycles: ptrU(0)}, {FailCycles: ptrU(21)},
		{RestoreCycles: ptrU(0)}, {RestoreCycles: ptrU(21)},
		{RestoreGapSec: ptrU(3601)},
	}
	before := a.config.DNSProxy.Health
	for i := range bad {
		if err := a.SetDnsUpstreams(nil, &bad[i]); !errors.Is(err, app.ErrDnsUpstreamsInvalid) {
			t.Fatalf("патч %+v должен отвергаться, got %v", bad[i], err)
		}
	}
	if a.config.DNSProxy.Health != before {
		t.Fatalf("после отказов модель не должна меняться")
	}

	// addrs + health вместе: меняется и список, и политика
	if err := a.SetDnsUpstreams([]string{"9.9.9.9"}, &models.AppConfigDNSProxyHealthPatch{IntervalSec: ptrU(60)}); err != nil {
		t.Fatalf("список+патч отвергнут: %v", err)
	}
	if len(a.config.DNSProxy.UpstreamList()) != 1 || a.config.DNSProxy.UpstreamList()[0].Address != "9.9.9.9" {
		t.Fatalf("список не заменён: %+v", a.config.DNSProxy.UpstreamList())
	}
	if a.config.DNSProxy.Health.Interval != time.Minute {
		t.Fatalf("интервал из комбинированной записи: %+v", a.config.DNSProxy.Health)
	}
}

func ptrU(v uint) *uint { return &v }
