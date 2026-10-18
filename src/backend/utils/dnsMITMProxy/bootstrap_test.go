package dnsMITMProxy

// Тесты бутстрап-резолва (rev12): DoH/DoT-апстрим ПО ИМЕНИ хоста решается
// через plain-апстримы каскада (локальный UDP-DNS в тестах), диал - по IP,
// SNI/серт проверяются по имени. До фикса диал шёл системным резолвером -
// на машине без записи о doh.test (и на OpenWrt с ::1 в resolv.conf) эти
// тесты падали с lookup-ошибкой ещё на соединении.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const bootstrapTestHost = "doh.test"

// countingBootstrapDNS - фейковый бутстрап-DNS: A-ответ по имени (пустой
// успех, если имени нет), a6 - AAAA-ответ для всех имён, hits - счётчик
// принятых запросов (по нему проверяется кэш).
type countingBootstrapDNS struct {
	mu      sync.Mutex
	answers map[string]string
	a6      string
	hits    int64
}

func newCountingBootstrapDNS(answers map[string]string) *countingBootstrapDNS {
	return &countingBootstrapDNS{answers: answers}
}

func (s *countingBootstrapDNS) setA6(v string) {
	s.mu.Lock()
	s.a6 = v
	s.mu.Unlock()
}

func (s *countingBootstrapDNS) queryCount() int64 { return atomic.LoadInt64(&s.hits) }

// serveBootstrapDNS - UDP-сервер бутстрапа, addr для списка апстримов.
func serveBootstrapDNS(t *testing.T, st *countingBootstrapDNS) string {
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
			atomic.AddInt64(&st.hits, 1)
			m := new(dns.Msg)
			m.SetReply(q)
			st.mu.Lock()
			a4 := st.answers[strings.TrimSuffix(q.Question[0].Name, ".")]
			a6 := st.a6
			st.mu.Unlock()
			switch q.Question[0].Qtype {
			case dns.TypeA:
				if a4 != "" {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP(a4),
					})
				}
			case dns.TypeAAAA:
				if a6 != "" {
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: net.ParseIP(a6),
					})
				}
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

// namedCert - самоподписанный серт с DNS-SAN host и пул с ним: проверка
// серта ПО ИМЕНИ остаётся честной (не InsecureSkipVerify).
func namedCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// serveNamedDoT - локальный DoT-сервер с сертом на имя (принимает TLS,
// отвечает A-записью *ip).
func serveNamedDoT(t *testing.T, cert tls.Certificate, ip *string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				for {
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					req, err := dnsFramedRead(c)
					if err != nil {
						return
					}
					q := new(dns.Msg)
					if q.Unpack(req) != nil {
						return
					}
					resp, _ := answerMsg(q, *ip).Pack()
					if _, err := c.Write([]byte{byte(len(resp) >> 8), byte(len(resp))}); err != nil {
						return
					}
					if _, err := c.Write(resp); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// serveNamedDoH - локальный DoH-сервер (RFC 8484) с сертом на имя.
func serveNamedDoH(t *testing.T, cert tls.Certificate, ip *string) string {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		q := new(dns.Msg)
		if q.Unpack(body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp, _ := answerMsg(q, *ip).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	})
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

// namedUpstream - апстрим из сырого адреса с подменой TLS (серт на имя)
// и бутстрап-резолвером менеджера.
func namedUpstream(t *testing.T, raw string, ov *tls.Config, bs *bootstrapResolver) *upstream {
	t.Helper()
	p, err := ParseUpstreamAddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	return newUpstreamParsed(p, 2, ov, bs)
}

// proxyFor - прокси поверх готового менеджера (клиентский путь с делением
// бюджета).
func proxyFor(m *upstreamManager, timeout time.Duration) *DNSMITMProxy {
	return &DNSMITMProxy{
		bufferPool: &sync.Pool{New: func() interface{} {
			buf := make([]byte, dns.MaxMsgSize)
			return &buf
		}},
		upstreams: m,
		semaphore: make(chan struct{}, 8),
		timeout:   timeout,
	}
}

func bootstrapTestTLS(ov *tls.Config, pool *x509.CertPool) *tls.Config {
	c := ov.Clone()
	c.ServerName = bootstrapTestHost
	c.RootCAs = pool
	c.MinVersion = tls.VersionTLS12
	return c
}

// ГЛАВНЫЙ кейс rev12 (живой кейс 0.42): DoT по имени в каскаде с plain -
// имя решается через plain-апстрим, диал по IP, серт по имени; кэш не
// дёргает бутстрап-DNS повторно. До фикса падало на системном резолве.
func TestBootstrapDoTByName(t *testing.T) {
	clean := "204.8.99.144"
	bs := newCountingBootstrapDNS(map[string]string{bootstrapTestHost: "127.0.0.1"})
	bsAddr := serveBootstrapDNS(t, bs)
	cert, pool := namedCert(t, bootstrapTestHost)
	dotAddr := serveNamedDoT(t, cert, &clean)
	_, port, err := net.SplitHostPort(dotAddr)
	if err != nil {
		t.Fatal(err)
	}

	m := newUpstreamManager([]string{bsAddr}, 2, UpstreamHealth{Enabled: false})
	defer m.close()
	u := namedUpstream(t, "tls://"+bootstrapTestHost+":"+port, bootstrapTestTLS(insecureTLS(), pool), m.bs)

	ok, why := canaryProbe(context.Background(), u, 3*time.Second)
	if !ok || why != "" {
		t.Fatalf("canary DoT по имени: ok=%v why=%q", ok, why)
	}
	if n := bs.queryCount(); n == 0 {
		t.Fatalf("бутстрап-сервер не опрошен")
	}
	before := bs.queryCount()
	if ok, why := canaryProbe(context.Background(), u, 3*time.Second); !ok || why != "" {
		t.Fatalf("canary повторно: ok=%v why=%q", ok, why)
	}
	if n := bs.queryCount(); n != before {
		t.Fatalf("кэш: бутстрап-сервер дёрнут повторно (%d -> %d)", before, n)
	}

	// клиентский путь: менеджер без plain (упрётся в фолбэк), пул DoT
	// диалится по бутстрап-IP, ответ доходит с фреймингом
	oldFallback := bootstrapFallbackServer
	bootstrapFallbackServer = bsAddr
	defer func() { bootstrapFallbackServer = oldFallback }()
	m2 := newUpstreamManager(nil, 2, UpstreamHealth{Enabled: false})
	defer m2.close()
	m2.tlsOverride = bootstrapTestTLS(insecureTLS(), pool)
	m2.update([]string{"tls://" + bootstrapTestHost + ":" + port}, UpstreamHealth{Enabled: false})

	px := proxyFor(m2, 3*time.Second)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	req, _ := q.Pack()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := px.requestUpstreamDNS(ctx, req, "udp")
	if err != nil {
		t.Fatalf("клиентский обмен через DoT по имени: %v", err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(resp); err != nil || len(r.Answer) == 0 || r.Answer[0].(*dns.A).A.String() != clean {
		t.Fatalf("ответ мимо DoT: %v %+v", err, r.Answer)
	}
}

// То же для DoH: имя из https://host/... решается бутстрапом, диал по IP,
// Host-заголовок и серт остаются по имени.
func TestBootstrapDoHByName(t *testing.T) {
	clean := "204.8.99.146"
	bs := newCountingBootstrapDNS(map[string]string{bootstrapTestHost: "127.0.0.1"})
	bsAddr := serveBootstrapDNS(t, bs)
	cert, pool := namedCert(t, bootstrapTestHost)
	dohSrv := serveNamedDoH(t, cert, &clean)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(dohSrv, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	m := newUpstreamManager([]string{bsAddr}, 2, UpstreamHealth{Enabled: false})
	defer m.close()
	u := namedUpstream(t, "https://"+bootstrapTestHost+":"+port+"/dns-query", bootstrapTestTLS(insecureTLS(), pool), m.bs)

	ok, why := canaryProbe(context.Background(), u, 3*time.Second)
	if !ok || why != "" {
		t.Fatalf("canary DoH по имени: ok=%v why=%q", ok, why)
	}
	if n := bs.queryCount(); n == 0 {
		t.Fatalf("бутстрап-сервер не опрошен")
	}
	before := bs.queryCount()
	if ok, why := canaryProbe(context.Background(), u, 3*time.Second); !ok || why != "" {
		t.Fatalf("canary повторно: ok=%v why=%q", ok, why)
	}
	if n := bs.queryCount(); n != before {
		t.Fatalf("кэш: бутстрап-сервер дёрнут повторно (%d -> %d)", before, n)
	}

	oldFallback := bootstrapFallbackServer
	bootstrapFallbackServer = bsAddr
	defer func() { bootstrapFallbackServer = oldFallback }()
	m2 := newUpstreamManager(nil, 2, UpstreamHealth{Enabled: false})
	defer m2.close()
	m2.tlsOverride = bootstrapTestTLS(insecureTLS(), pool)
	m2.update([]string{"https://" + bootstrapTestHost + ":" + port + "/dns-query"}, UpstreamHealth{Enabled: false})

	px := proxyFor(m2, 3*time.Second)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	req, _ := q.Pack()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := px.requestUpstreamDNS(ctx, req, "udp")
	if err != nil {
		t.Fatalf("клиентский обмен через DoH по имени: %v", err)
	}
	r := new(dns.Msg)
	if err := r.Unpack(resp); err != nil || len(r.Answer) == 0 || r.Answer[0].(*dns.A).A.String() != clean {
		t.Fatalf("ответ мимо DoH: %v %+v", err, r.Answer)
	}
}

// TTL кэша: свежая запись не опрашивает сервер, протухшая - опрашивает;
// при отказе резолва живой ещё один TTL на устаревшем ответе.
func TestBootstrapCacheTTLAndStale(t *testing.T) {
	oldFallback := bootstrapFallbackServer
	bootstrapFallbackServer = "127.0.0.1:1" // за пределы машины не ходим
	defer func() { bootstrapFallbackServer = oldFallback }()

	bs := newCountingBootstrapDNS(map[string]string{"cache.test": "127.0.0.2"})
	bsAddr := serveBootstrapDNS(t, bs)

	r := newBootstrapResolver(func() []string { return []string{bsAddr} })
	base := time.Now()
	r.now = func() time.Time { return base }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := r.lookup(ctx, "cache.test")
	if err != nil || len(ips) != 1 || ips[0].String() != "127.0.0.2" {
		t.Fatalf("первый резолв: %v %v", ips, err)
	}
	if n := bs.queryCount(); n != 1 {
		t.Fatalf("первый резолв дал %d запросов, хочу 1", n)
	}
	if _, err := r.lookup(ctx, "cache.test"); err != nil {
		t.Fatalf("второй резолв: %v", err)
	}
	if n := bs.queryCount(); n != 1 {
		t.Fatalf("кэш не сработал: %d запросов", n)
	}

	base = base.Add(6 * time.Minute) // TTL 5м истёк
	if _, err := r.lookup(ctx, "cache.test"); err != nil {
		t.Fatalf("резолв после TTL: %v", err)
	}
	if n := bs.queryCount(); n != 2 {
		t.Fatalf("после TTL ждём свежий резолв, запросов %d", n)
	}

	// резолв умер (пустые ответы): живём на устаревшей записи
	bs.mu.Lock()
	delete(bs.answers, "cache.test")
	bs.mu.Unlock()
	base = base.Add(6 * time.Minute)
	ips, err = r.lookup(ctx, "cache.test")
	if err != nil || len(ips) != 1 || ips[0].String() != "127.0.0.2" {
		t.Fatalf("stale при мёртвом резолве: %v %v", ips, err)
	}
}

// мёртвый первый plain - фолбэк на резервный сервер (в тесте он локальный)
func TestBootstrapFallbackServer(t *testing.T) {
	oldFallback := bootstrapFallbackServer
	bootstrapFallbackServer = "127.0.0.1:1" // мёртв: обычный кейс без подмены
	defer func() { bootstrapFallbackServer = oldFallback }()

	bs := newCountingBootstrapDNS(map[string]string{"fb.test": "127.0.0.3"})
	bsAddr := serveBootstrapDNS(t, bs)
	bootstrapFallbackServer = bsAddr // фолбэк указывает на живой локальный

	r := newBootstrapResolver(func() []string { return []string{"127.0.0.1:1"} })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := r.lookup(ctx, "fb.test")
	if err != nil || len(ips) != 1 || ips[0].String() != "127.0.0.3" {
		t.Fatalf("фолбэк: %v %v", ips, err)
	}
	if n := bs.queryCount(); n == 0 {
		t.Fatalf("фолбэк-сервер не опрошен")
	}
}

// в бутстрап-серверы годятся только IP-plain: plain с именем - цикл,
// DoT/DoH - не plain вовсе
func TestBootstrapServersFilter(t *testing.T) {
	clean := "204.8.99.144"
	bs := newCountingBootstrapDNS(nil)
	bsAddr := serveBootstrapDNS(t, bs)
	dotAddr := serveNamedDoT(t, mustNamedCert(t), &clean)

	m := newUpstreamManager([]string{"dns.internal:53", bsAddr, "tls://" + dotAddr}, 2, UpstreamHealth{Enabled: false})
	defer m.close()
	got := m.bootstrapServers()
	if len(got) != 1 || got[0] != bsAddr {
		t.Fatalf("bootstrapServers = %v, хочу [%s]", got, bsAddr)
	}
}

func mustNamedCert(t *testing.T) tls.Certificate {
	cert, _ := namedCert(t, bootstrapTestHost)
	return cert
}

// порядок перебора: живые бутстрап-серверы вперёд - мёртвый plain уходит
// в хвост, живой резолвит имя (кто ответил - видно по IP в ответе)
func TestBootstrapServersAliveFirst(t *testing.T) {
	oldFallback := bootstrapFallbackServer
	bootstrapFallbackServer = "127.0.0.1:1"
	defer func() { bootstrapFallbackServer = oldFallback }()

	spoof := "6.6.6.6"
	clean := "204.8.99.144"
	dead := fakeUpstreamUDP(t, &spoof)
	live := fakeUpstreamUDP(t, &clean)

	h := UpstreamHealth{Enabled: true, Interval: 10 * time.Millisecond, Timeout: 500 * time.Millisecond, FailCycles: 1, RestoreCycles: 1, RestoreGap: 0}
	m := newUpstreamManager([]string{dead, live}, 2, h)
	defer m.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.start(ctx)

	// ждём, пока канарейка пометит спуфера мёртвым
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !m.upstreams[0].isAlive() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m.upstreams[0].isAlive() {
		t.Fatalf("спуфер не помечен мёртвым")
	}
	if got := m.bootstrapServers(); len(got) != 2 || got[0] != live || got[1] != dead {
		t.Fatalf("живой бутстрап-сервер должен идти первым: %v", got)
	}

	r := newBootstrapResolver(m.bootstrapServers)
	ips, err := r.lookup(ctx, "order.test")
	if err != nil || len(ips) != 1 || ips[0].String() != clean {
		t.Fatalf("резолв должен прийти с живого сервера: %v %v", ips, err)
	}
}
