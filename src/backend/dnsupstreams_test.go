package magitrickle

import (
	"errors"
	"testing"

	"magitrickle/app"
	"magitrickle/constant"
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

	if err := a.SetDnsUpstreams(nil); !errors.Is(err, app.ErrDnsUpstreamsInvalid) {
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
