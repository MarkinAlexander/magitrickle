package dnsMITMProxy

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeUpstreamUDP - фейковый DNS-апстрим: отвечает A-записью с *answer
// (или пустым успехом, если *answer == ""), значение читается на каждый
// запрос - тест может переключать «чистый/отравленный» на лету.
func fakeUpstreamUDP(t *testing.T, answer *string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, dns.MaxMsgSize)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if err := q.Unpack(buf[:n]); err != nil {
				continue
			}
			m := new(dns.Msg)
			m.SetReply(q)
			if ip := *answer; ip != "" {
				m.Answer = append(m.Answer, &dns.A{
					Hdr:  dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:    net.ParseIP(ip),
				})
			}
			resp, err := m.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func testQuery(t *testing.T) []byte {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	req, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func candidateAddrs(m *upstreamManager) []string {
	var out []string
	for _, u := range m.candidates() {
		out = append(out, u.addr)
	}
	return out
}

// клиентский запрос: мёртвый активный апстрим не роняет ответ - перебор
// доходит до живого; все мертвы - ошибка (деградация по приоритету
// проверяется тем, что «отравленный» апстрим всё ещё отдаёт транспорт)
func TestRequestUpstreamFailover(t *testing.T) {
	clean := "204.8.99.144"
	alive := fakeUpstreamUDP(t, &clean)
	p := NewDNSMITMProxy([]string{"127.0.0.1:1", alive}, 2, 4, time.Second, UpstreamHealth{Enabled: false})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := p.requestUpstreamDNS(ctx, testQuery(t), "udp")
	if err != nil {
		t.Fatalf("фейловер на живой: %v", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(resp); err != nil || len(m.Answer) != 1 {
		t.Fatalf("ответ без A: %v %+v", err, m.Answer)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// одиночный мёртвый - старое поведение: ошибка наверх
	p1 := NewDNSMITMProxy([]string{"127.0.0.1:1"}, 2, 4, time.Second, UpstreamHealth{Enabled: false})
	_, err = p1.requestUpstreamDNS(ctx, testQuery(t), "udp")
	if err == nil || !strings.Contains(err.Error(), "all upstreams failed") {
		t.Fatalf("одиночный мёртвый: %v", err)
	}
	if err := p1.Close(); err != nil {
		t.Fatal(err)
	}
}

// K/M-гистерезис: K неудач канарейки подряд -> dead (уходит вниз списка
// кандидатов), M чистых подряд -> alive (возврат наверх)
func TestCanaryMarkingKM(t *testing.T) {
	spoof := "6.6.6.6"
	clean := "204.8.99.144"
	a := spoof // сначала отравлен
	alive := fakeUpstreamUDP(t, &a)
	first := fakeUpstreamUDP(t, &clean)
	h := UpstreamHealth{Enabled: true, Interval: 10 * time.Millisecond, Timeout: 500 * time.Millisecond, FailCycles: 2, RestoreCycles: 2, RestoreGap: 0}
	m := newUpstreamManager([]string{alive, first}, 2, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.start(ctx)
	defer m.close()

	waitFor := func(want []string, label string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if got := strings.Join(candidateAddrs(m), ","); got == strings.Join(want, ",") {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("%s: кандидаты = %v, want %v", label, candidateAddrs(m), want)
	}
	// K=2 неудачи подряд: отравленный уходит вниз
	waitFor([]string{first, alive}, "после K неудач")

	// канарейка превращается в чистую: M=2 успеха -> возврат наверх
	a = clean
	waitFor([]string{alive, first}, "после M успехов")
}

// restoreGap: чистые пробы есть, но возврат наверх не чаще раза в R
func TestRestoreGapBlocksFlap(t *testing.T) {
	spoof := "6.6.6.6"
	clean := "204.8.99.144"
	a := spoof
	alive := fakeUpstreamUDP(t, &a)
	first := fakeUpstreamUDP(t, &clean)
	h := UpstreamHealth{Enabled: true, Interval: 10 * time.Millisecond, Timeout: 500 * time.Millisecond, FailCycles: 1, RestoreCycles: 1, RestoreGap: time.Hour}
	m := newUpstreamManager([]string{alive, first}, 2, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.start(ctx)
	defer m.close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !m.upstreams[0].isAlive() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m.upstreams[0].isAlive() {
		t.Fatalf("K=1 не пометил мёртвым")
	}
	a = clean // чистая канарейка есть, но gap=1h не пускает наверх
	time.Sleep(80 * time.Millisecond)
	if m.upstreams[0].isAlive() {
		t.Fatalf("restoreGap проигнорирован")
	}
}

// все апстримы отравлены: DNS не отказываем - транспорт всё равно отвечает
// (клиент получает яд, воркер продолжает пробы; деградация по приоритету)
func TestDegradedServing(t *testing.T) {
	spoof := "6.6.6.6"
	a := spoof
	s1 := fakeUpstreamUDP(t, &a)
	s2 := fakeUpstreamUDP(t, &a)
	p := NewDNSMITMProxy([]string{s1, s2}, 2, 4, time.Second, UpstreamHealth{Enabled: false})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := p.requestUpstreamDNS(ctx, testQuery(t), "udp")
	if err != nil {
		t.Fatalf("деградация не должна отказывать в ответе: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

// горячая подмена списка: выживший сохраняет здоровье, исчезнувший закрыт,
// новый добавлен, дубликат схлопнут
func TestUpdateHotSwap(t *testing.T) {
	clean := "204.8.99.144"
	a1 := fakeUpstreamUDP(t, &clean)
	a2 := fakeUpstreamUDP(t, &clean)
	a3 := fakeUpstreamUDP(t, &clean)
	m := newUpstreamManager([]string{a1, a2}, 2, UpstreamHealth{Enabled: false})
	m.upstreams[0].alive = false // «умер» до подмены
	removed := m.upstreams[0]

	m.update([]string{a2, a2, a3, ""}, UpstreamHealth{Enabled: false})
	got := candidateAddrs(m)
	if strings.Join(got, ",") != a2+","+a3 {
		t.Fatalf("после update: %v", got)
	}
	if !m.upstreams[0].isAlive() || m.upstreams[0].addr != a2 {
		t.Fatalf("выживший потерял стейт/порядок: %+v", m.upstreams[0])
	}
	if _, err := removed.udp.Get(context.Background()); err == nil {
		// Get создаёт новое соединение - закрытый пул должен отказать
		t.Fatalf("закрытый пул a1 ещё жив")
	}
	m.close()
}

// канарейка: чистый ответ - true; отрава/пустой - false с причиной
func TestCanaryProbeVerdicts(t *testing.T) {
	clean := "204.8.99.144"
	s := fakeUpstreamUDP(t, &clean)
	u := newUpstream(s, 2, nil, nil)
	ok, why := canaryProbe(context.Background(), u, time.Second)
	if !ok || why != "" {
		t.Fatalf("clean: ok=%v why=%q", ok, why)
	}

	spoof := "6.6.6.6"
	s = fakeUpstreamUDP(t, &spoof)
	u = newUpstream(s, 2, nil, nil)
	ok, why = canaryProbe(context.Background(), u, time.Second)
	if ok || !strings.Contains(why, "канонических") {
		t.Fatalf("spoof: ok=%v why=%q", ok, why)
	}

	empty := ""
	s = fakeUpstreamUDP(t, &empty)
	u = newUpstream(s, 2, nil, nil)
	ok, why = canaryProbe(context.Background(), u, time.Second)
	if ok || why == "" {
		t.Fatalf("пустой ответ: ok=%v why=%q", ok, why)
	}

	u = newUpstream("127.0.0.1:1", 2, nil, nil)
	ok, why = canaryProbe(context.Background(), u, 300*time.Millisecond)
	if ok || why == "" {
		t.Fatalf("мёртвый: ok=%v why=%q", ok, why)
	}
}

// снапшот стейта (API rev8): порядок апстримов сохраняется, active -
// первый живой, у мёртвого - причина и момент переключения
func TestUpstreamsSnapshot(t *testing.T) {
	clean := "204.8.99.144"
	a1 := fakeUpstreamUDP(t, &clean)
	a2 := fakeUpstreamUDP(t, &clean)
	h := UpstreamHealth{Enabled: true, Interval: time.Second, Timeout: 500 * time.Millisecond, FailCycles: 1, RestoreCycles: 1, RestoreGap: 0}
	m := newUpstreamManager([]string{a1, a2}, 2, h)

	// второй апстрим «умер»: K=1 неудача подряд
	m.mark(m.upstreams[1], false, "dial: i/o timeout")
	snap := m.snapshot()
	if len(snap.Upstreams) != 2 {
		t.Fatalf("в снапшоте %d апстримов", len(snap.Upstreams))
	}
	if snap.Upstreams[0].Address != a1 || !snap.Upstreams[0].Alive || !snap.Upstreams[0].Active {
		t.Fatalf("первый (живой) неверен: %+v", snap.Upstreams[0])
	}
	dead := snap.Upstreams[1]
	if dead.Address != a2 || dead.Alive || dead.Active {
		t.Fatalf("второй должен быть мёртвым и не активным: %+v", dead)
	}
	if dead.Reason != "dial: i/o timeout" || dead.LastSwap.IsZero() {
		t.Fatalf("причина/момент переключения потеряны: %+v", dead)
	}
	if !snap.Health.Enabled || snap.Health.FailCycles != 1 {
		t.Fatalf("политика зондов не в снапшоте: %+v", snap.Health)
	}

	// оба мертвы: active никому не ставится; обновление политики видно
	m.mark(m.upstreams[0], false, "read: timeout")
	snap = m.snapshot()
	for _, u := range snap.Upstreams {
		if u.Active {
			t.Fatalf("active при всех мёртвых: %+v", snap.Upstreams)
		}
	}
	m.update([]string{a1}, UpstreamHealth{Enabled: false})
	m.upstreams[0].alive = true // выживший восстановлен вручную (политика update'ом обнулилась)
	if snap := m.snapshot(); snap.Health.Enabled || len(snap.Upstreams) != 1 || !snap.Upstreams[0].Active {
		t.Fatalf("после update: %+v", snap)
	}
	m.close()

	// ноль апстримов (после close) - честный пустой снапшот без паники
	snap = m.snapshot()
	if len(snap.Upstreams) != 0 {
		t.Fatalf("после close снапшот непустой: %+v", snap.Upstreams)
	}
}
