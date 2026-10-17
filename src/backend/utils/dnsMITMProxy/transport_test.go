package dnsMITMProxy

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
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseUpstreamAddr(t *testing.T) {
	cases := []struct {
		in         string
		kind       upKind
		addr       string
		dial       string
		serverName string
	}{
		{"8.8.8.8:53", upPlain, "8.8.8.8:53", "8.8.8.8:53", ""},
		{"tls://1.1.1.1", upDoT, "tls://1.1.1.1:853", "1.1.1.1:853", "1.1.1.1"},
		{"tls://dns.google:8853", upDoT, "tls://dns.google:8853", "dns.google:8853", "dns.google"},
		{"https://dns.google", upDoH, "https://dns.google:443/dns-query", "", "dns.google"},
		{"https://1.1.1.1/dns-query", upDoH, "https://1.1.1.1:443/dns-query", "", "1.1.1.1"},
	}
	for _, c := range cases {
		p, err := ParseUpstreamAddr(c.in)
		if err != nil {
			t.Fatalf("ParseUpstreamAddr(%q): %v", c.in, err)
		}
		if p.kind != c.kind || p.addr != c.addr || p.dialAddr != c.dial || p.serverName != c.serverName {
			t.Fatalf("ParseUpstreamAddr(%q) = %+v, хочу kind=%v addr=%q dial=%q sni=%q",
				c.in, p, c.kind, c.addr, c.dial, c.serverName)
		}
	}
	for _, bad := range []string{"tls://", "https://", "http://x", "quic://x", "tls://1.1.1.1/p", "tls://x:0", "://"} {
		if _, err := ParseUpstreamAddr(bad); err == nil {
			t.Errorf("ParseUpstreamAddr(%q) должен ошибаться", bad)
		}
	}
}

// selfSignedCert - сертификат с IP-SAN 127.0.0.1 для локальных TLS-серверов.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}

// answerMsg - DNS-ответ на q с A-записью ip (или пустой успех при ip=="").
func answerMsg(q *dns.Msg, ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	if ip != "" {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip),
		})
	}
	return m
}

// serveDoT - локальный DoT-сервер: отвечает на каждый запрос ip (или пусто).
func serveDoT(t *testing.T, ip *string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)}, MinVersion: tls.VersionTLS12,
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
				defer c.Close()
				for {
					c.SetDeadline(time.Now().Add(5 * time.Second))
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

// dnsFramedRead - чтение одного length-prefixed сообщения.
func dnsFramedRead(c net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, lenBuf); err != nil {
		return nil, err
	}
	n := int(lenBuf[0])<<8 | int(lenBuf[1])
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// serveDoH - локальный DoH-сервер (RFC 8484); статус для отказа.
func serveDoH(t *testing.T, ip *string, status *int) string {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *status != 0 {
			w.WriteHeader(*status)
			return
		}
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
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL
}

func dotUpstream(t *testing.T, addr string) *upstream {
	t.Helper()
	p, err := ParseUpstreamAddr("tls://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	return newUpstreamParsed(p, 2, insecureTLS())
}

func dohUpstream(t *testing.T, url string) *upstream {
	t.Helper()
	p, err := ParseUpstreamAddr(url)
	if err != nil {
		t.Fatal(err)
	}
	return newUpstreamParsed(p, 2, insecureTLS())
}

// DoT: канарейка чистая/отравленная/мёртвая + клиентский обмен с фреймингом
func TestDoTProbeAndExchange(t *testing.T) {
	clean := "204.8.99.144"
	addr := serveDoT(t, &clean)
	u := dotUpstream(t, addr)
	t.Cleanup(u.closeAll)

	ok, why := canaryProbe(context.Background(), u, 2*time.Second)
	if !ok || why != "" {
		t.Fatalf("canary: ok=%v why=%q", ok, why)
	}

	px := &DNSMITMProxy{timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	req, _ := q.Pack()
	resp, err := px.exchangeUpstream(context.Background(), u, req, "udp") // kind=DoT: сеть клиента не важна
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(resp); err != nil || len(m.Answer) == 0 {
		t.Fatalf("ответ: %v %+v", err, m)
	}

	spoof := "6.6.6.6"
	u2 := dotUpstream(t, serveDoT(t, &spoof))
	t.Cleanup(u2.closeAll)
	ok, why = canaryProbe(context.Background(), u2, 2*time.Second)
	if ok || !strings.Contains(why, "канонических") {
		t.Fatalf("отрава должна ловиться: ok=%v why=%q", ok, why)
	}

	u3 := dotUpstream(t, "127.0.0.1:1")
	t.Cleanup(u3.closeAll)
	ok, why = canaryProbe(context.Background(), u3, 300*time.Millisecond)
	if ok || why == "" {
		t.Fatalf("мёртвый DoT: ok=%v why=%q", ok, why)
	}
}

// DoH: канарейка + клиентский обмен + HTTP-отказ считается ошибкой транспорта
func TestDoHProbeAndExchange(t *testing.T) {
	clean := "204.8.99.146"
	status := 0
	url := serveDoH(t, &clean, &status)
	u := dohUpstream(t, url)
	t.Cleanup(u.closeAll)

	ok, why := canaryProbe(context.Background(), u, 2*time.Second)
	if !ok || why != "" {
		t.Fatalf("canary: ok=%v why=%q", ok, why)
	}

	px := &DNSMITMProxy{timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	req, _ := q.Pack()
	resp, err := px.exchangeUpstream(context.Background(), u, req, "udp")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(resp); err != nil || len(m.Answer) == 0 {
		t.Fatalf("ответ: %v %+v", err, m)
	}

	status = http.StatusInternalServerError
	ok, why = canaryProbe(context.Background(), u, 2*time.Second)
	if ok || !strings.Contains(why, "500") {
		t.Fatalf("HTTP-отказ: ok=%v why=%q", ok, why)
	}
}

// менеджер: DoT/DoH апстримы живут в одном списке с plain, канонический
// адрес - идентификатор для горячего обновления (keep по addr)
func TestManagerMixedTransports(t *testing.T) {
	clean := "204.8.99.144"
	dotAddr := serveDoT(t, &clean)
	plain := fakeUpstreamUDP(t, &clean)

	m := newUpstreamManager([]string{plain, "tls://" + dotAddr}, 2, UpstreamHealth{Enabled: false})
	ups := m.candidates()
	if len(ups) != 2 || ups[0].kind != upPlain || ups[1].kind != upDoT {
		t.Fatalf("список: %+v", ups)
	}
	// горячее обновление: DoT выживает (тот же addr), DoH добавляется, plain уходит
	m.update([]string{"tls://" + dotAddr, "https://dns.google"}, UpstreamHealth{Enabled: false})
	ups = m.candidates()
	if len(ups) != 2 || ups[0].kind != upDoT || ups[1].kind != upDoH {
		t.Fatalf("после update: %+v", ups)
	}
	m.close()
}
