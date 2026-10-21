package dnsMITMProxy

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// NormalizeZone: lowercase, trim, без хвостовой точки; кривой ввод -> ""
func TestNormalizeZone(t *testing.T) {
	for in, want := range map[string]string{
		"corp.example.com":   "corp.example.com",
		"  CORP.Example.com.": "corp.example.com",
		"\tLocal ":            "local",
	} {
		if got := NormalizeZone(in); got != want {
			t.Fatalf("NormalizeZone(%q) = %q, хочу %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "  ", ".", "..", "a..b", "a b", "corp/example.com", "tls://corp.example.com"} {
		if got := NormalizeZone(bad); got != "" {
			t.Fatalf("NormalizeZone(%q) = %q, хочу пусто", bad, got)
		}
	}
}

// longest-suffix матч: точное имя, поддомен, регистр, самая длинная зона
// побеждает, чужое имя - nil
func TestZoneMatch(t *testing.T) {
	p := NewDNSMITMProxy([]string{"127.0.0.1:1"}, 2, 4, time.Second, UpstreamHealth{Enabled: false})
	defer func() { _ = p.Close() }()
	p.UpdateZones([]ZoneRoute{
		{Zone: "example.com", UpstreamAddrs: []string{"127.0.0.1:1"}},
		{Zone: "corp.example.com", UpstreamAddrs: []string{"127.0.0.1:2"}},
	}, UpstreamHealth{Enabled: false})

	cases := []struct {
		qname string
		want  string
	}{
		{"corp.example.com.", "corp.example.com."},
		{"host.CORP.example.com.", "corp.example.com."},
		{"example.com.", "example.com."},
		{"www.example.com.", "example.com."},
		{"ecorp.example.com.", "example.com."}, // поддомен зоны - тоже в зоне
		{"corp.example.com.evil.net.", ""},     // зона не справа - не матч
		{"other.net.", ""},
	}
	for _, c := range cases {
		e := p.matchZone(c.qname)
		got := ""
		if e != nil {
			got = e.suffix
		}
		if got != c.want {
			t.Fatalf("matchZone(%q) = %q, хочу %q", c.qname, got, c.want)
		}
	}
}

// роутинг: имя из зоны -> сервер зоны, чужое имя -> общий каскад
func TestZoneRouting(t *testing.T) {
	zoneIP, generalIP := "10.1.2.3", "10.9.9.9"
	zoneSrv := fakeUpstreamUDP(t, &zoneIP)
	generalSrv := fakeUpstreamUDP(t, &generalIP)
	p := NewDNSMITMProxy([]string{generalSrv}, 2, 4, time.Second, UpstreamHealth{Enabled: false})
	defer func() { _ = p.Close() }()
	p.UpdateZones([]ZoneRoute{{Zone: "corp.example.com", UpstreamAddrs: []string{zoneSrv}}}, UpstreamHealth{Enabled: false})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	q := func(name string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		return m
	}
	respBytes, err := p.processReq(ctx, &netAddrFake{}, pack(t, q("git.corp.example.com.")), "udp")
	if err != nil {
		t.Fatalf("зонный запрос: %v", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(respBytes); err != nil || len(m.Answer) != 1 {
		t.Fatalf("ответ зоны без A: %v %+v", err, m.Answer)
	}
	if m.Answer[0].(*dns.A).A.String() != zoneIP {
		t.Fatalf("зонный запрос ушёл мимо зоны: %v", m.Answer[0])
	}

	respBytes, err = p.processReq(ctx, &netAddrFake{}, pack(t, q("example.org.")), "udp")
	if err != nil {
		t.Fatalf("общий запрос: %v", err)
	}
	m = new(dns.Msg)
	if err := m.Unpack(respBytes); err != nil || len(m.Answer) != 1 {
		t.Fatalf("общий ответ без A: %v %+v", err, m.Answer)
	}
	if m.Answer[0].(*dns.A).A.String() != generalIP {
		t.Fatalf("общий запрос ушёл в зону: %v", m.Answer[0])
	}
}

// fail-closed: серверы зоны мертвы, FallbackOpen=false -> честный SERVFAIL
// (не таймаут и не ответ общего каскада); FallbackOpen=true -> общий каскад
func TestZoneFailClosed(t *testing.T) {
	generalIP := "10.9.9.9"
	generalSrv := fakeUpstreamUDP(t, &generalIP)

	newProxy := func(fallback bool) *DNSMITMProxy {
		p := NewDNSMITMProxy([]string{generalSrv}, 2, 4, time.Second, UpstreamHealth{Enabled: false})
		p.UpdateZones([]ZoneRoute{{
			Zone:          "corp.example.com",
			UpstreamAddrs: []string{"127.0.0.1:1"}, // мёртвый
			FallbackOpen:  fallback,
		}}, UpstreamHealth{Enabled: false})
		return p
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion("host.corp.example.com.", dns.TypeA)

	// fail-closed: SERVFAIL
	p := newProxy(false)
	defer func() { _ = p.Close() }()
	respBytes, err := p.processReq(ctx, &netAddrFake{}, pack(t, q), "udp")
	if err != nil {
		t.Fatalf("fail-closed должен отвечать SERVFAIL-пакетом, не ошибкой: %v", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(respBytes); err != nil {
		t.Fatalf("unpack SERVFAIL: %v", err)
	}
	if m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, хочу SERVFAIL", m.Rcode)
	}

	// fallback: общий каскад отвечает
	p2 := newProxy(true)
	defer func() { _ = p2.Close() }()
	respBytes, err = p2.processReq(ctx, &netAddrFake{}, pack(t, q), "udp")
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	m = new(dns.Msg)
	if err := m.Unpack(respBytes); err != nil || len(m.Answer) != 1 {
		t.Fatalf("fallback-ответ без A: %v %+v", err, m.Answer)
	}
	if m.Answer[0].(*dns.A).A.String() != generalIP {
		t.Fatalf("fallback ответил не общим каскадом: %v", m.Answer[0])
	}
}

// горячая подмена таблицы: выжившая зона сохраняет менеджер (и стейт
// здоровья), исчезнувшая закрывается, новая появляется
func TestUpdateZonesHotSwap(t *testing.T) {
	p := NewDNSMITMProxy([]string{"127.0.0.1:1"}, 2, 4, time.Second, UpstreamHealth{Enabled: false})
	defer func() { _ = p.Close() }()
	ip := "10.1.2.3"
	alive := fakeUpstreamUDP(t, &ip)
	h := UpstreamHealth{Enabled: true, FailCycles: 1, RestoreCycles: 2}
	p.UpdateZones([]ZoneRoute{
		{Zone: "a.example.com", UpstreamAddrs: []string{alive}},
		{Zone: "b.example.com", UpstreamAddrs: []string{"127.0.0.1:1"}},
	}, h)

	snaps := p.ZonesSnapshot()
	if len(snaps) != 2 {
		t.Fatalf("после первого UpdateZones зон: %d", len(snaps))
	}
	var aMgr = func() *upstreamManager {
		p.zonesMu.RLock()
		defer p.zonesMu.RUnlock()
		for _, e := range p.zones {
			if e.suffix == "a.example.com." {
				return e.mgr
			}
		}
		return nil
	}()
	if aMgr == nil {
		t.Fatal("менеджер зоны a не найден")
	}
	// помечаем апстрим зоны a мёртвым - стейт должен пережить подмену
	aMgr.mark(aMgr.upstreams[0], false, "test")

	p.UpdateZones([]ZoneRoute{
		{Zone: "a.example.com", UpstreamAddrs: []string{alive}, FallbackOpen: true},
		{Zone: "c.example.com", UpstreamAddrs: []string{alive}},
	}, h)

	p.zonesMu.RLock()
	var kept *upstreamManager
	var bFound, cFound, aFallback bool
	for _, e := range p.zones {
		switch e.suffix {
		case "a.example.com.":
			kept = e.mgr
			aFallback = e.fallbackOpen
		case "b.example.com.":
			bFound = true
		case "c.example.com.":
			cFound = true
		}
	}
	p.zonesMu.RUnlock()
	if kept == nil || kept != aMgr {
		t.Fatal("менеджер выжившей зоны подменён (потерян стейт)")
	}
	if !aFallback {
		t.Fatal("fallback-флаг выжившей зоны не обновился")
	}
	if bFound {
		t.Fatal("зона b осталась в таблице")
	}
	if !cFound {
		t.Fatal("новая зона c не появилась")
	}
	// стейт здоровья пережил горячую подмену: апстрим всё ещё мёртв
	if kept.upstreams[0].isAlive() {
		t.Fatal("стейт здоровья выжившей зоны потерян")
	}
}

// liveness-зонд: любой валидный ответ (в т.ч. пустой успех) = жив,
// мёртвый адрес = не жив; зонный менеджер зондирует liveness, а не
// канарейку
func TestLivenessProbeAndMarking(t *testing.T) {
	empty := ""
	srv := fakeUpstreamUDP(t, &empty) // отвечает успехом без A (NXDOMAIN-подобно)
	u := newUpstream(srv, 2, nil, nil)
	ok, why := livenessProbe(context.Background(), u, "corp.example.com", time.Second)
	if !ok {
		t.Fatalf("пустой успех должен считаться живым: %s", why)
	}
	dead := newUpstream("127.0.0.1:1", 2, nil, nil)
	if ok, _ = livenessProbe(context.Background(), dead, "corp.example.com", 300*time.Millisecond); ok {
		t.Fatal("мёртвый апстрим не должен быть живым")
	}

	// mark() зонного менеджера: 1 фейл (FailCycles=2 - ещё жив), 2 подряд -
	// мёртв; один валидный ответ (RestoreCycles=1) - жив снова
	m := newZoneUpstreamManager("corp.example.com.", []string{srv}, 2,
		UpstreamHealth{Enabled: true, FailCycles: 2, RestoreCycles: 1})
	if m.probeName != "corp.example.com" {
		t.Fatalf("probeName = %q", m.probeName)
	}
	m.mark(m.upstreams[0], false, "t")
	if !m.upstreams[0].isAlive() {
		t.Fatal("один фейл при K=2 не должен помечать мёртвым")
	}
	m.mark(m.upstreams[0], false, "t")
	if m.upstreams[0].isAlive() {
		t.Fatal("K фейлов подряд должны помечать мёртвым")
	}
	m.mark(m.upstreams[0], true, "")
	if !m.upstreams[0].isAlive() {
		t.Fatal("восстановление по валидному ответу не сработало (M=1)")
	}
}

func pack(t *testing.T, m *dns.Msg) []byte {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// netAddrFake - заглушка адреса клиента для processReq в тестах
type netAddrFake struct{}

func (netAddrFake) Network() string { return "udp" }
func (netAddrFake) String() string  { return "127.0.0.1:9999" }
