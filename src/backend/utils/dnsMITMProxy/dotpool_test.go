package dnsMITMProxy

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// serveDoTEx - serveDoT со счётчиком принятых соединений и режимами:
// closeAfterAnswer - сервер закрывает соединение после первого ответа
// (эмуляция смерти idle-conn на стороне сервера), wrongID - ответ с
// чужим ID (эмуляция повреждённого/чужого ответа).
func serveDoTEx(t *testing.T, ip *string, conns *int32, closeAfterAnswer, wrongID bool) string {
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
			if conns != nil {
				atomic.AddInt32(conns, 1)
			}
			go func(c net.Conn) {
				defer c.Close()
				answered := 0
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
					if wrongID {
						m := new(dns.Msg)
						if m.Unpack(resp) != nil {
							return
						}
						m.Id++
						resp, _ = m.Pack()
					}
					if _, err := c.Write([]byte{byte(len(resp) >> 8), byte(len(resp))}); err != nil {
						return
					}
					if _, err := c.Write(resp); err != nil {
						return
					}
					answered++
					if closeAfterAnswer && answered >= 1 {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// re_use: проба и клиентский обмен переиспользуют ОДНО соединение пула -
// ни новое рукопожатие, ни новый сокет на каждый обмен
func TestDoTConnectionReuse(t *testing.T) {
	clean := "204.8.99.144"
	var conns int32
	addr := serveDoTEx(t, &clean, &conns, false, false)
	u := dotUpstream(t, addr)
	t.Cleanup(u.closeAll)

	for i := 0; i < 2; i++ {
		if ok, why := canaryProbe(context.Background(), u, 2*time.Second); !ok {
			t.Fatalf("canary %d: %q", i+1, why)
		}
	}
	px := &DNSMITMProxy{timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	req, _ := q.Pack()
	if _, err := px.exchangeUpstream(context.Background(), u, req, "udp"); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if n := atomic.LoadInt32(&conns); n != 1 {
		t.Fatalf("сервер принял %d соединений, хочу 1 (переиспользование)", n)
	}
	if len(u.dot.pool) != 1 {
		t.Fatalf("в пуле %d соединений, хочу 1", len(u.dot.pool))
	}
}

// сервер закрыл idle-соединение: следующий обмен видит EOF, выбрасывает
// мёртвое и пересобирается ОДНИМ свежим диалом в пределах дедлайна
func TestDoTReconnectAfterServerClose(t *testing.T) {
	clean := "204.8.99.144"
	var conns int32
	addr := serveDoTEx(t, &clean, &conns, true, false)
	u := dotUpstream(t, addr)
	t.Cleanup(u.closeAll)

	if ok, why := canaryProbe(context.Background(), u, 2*time.Second); !ok {
		t.Fatalf("canary 1: %q", why)
	}
	time.Sleep(100 * time.Millisecond) // сервер успел закрыть соединение
	if ok, why := canaryProbe(context.Background(), u, 2*time.Second); !ok {
		t.Fatalf("canary 2 после смерти соединения: %q", why)
	}
	if n := atomic.LoadInt32(&conns); n != 2 {
		t.Fatalf("сервер принял %d соединений, хочу 2 (мёртвое выброшено, диал свежий)", n)
	}
	if len(u.dot.pool) != 1 {
		t.Fatalf("после реконнекта в пуле %d соединений, хочу 1", len(u.dot.pool))
	}
}

// чужой ID в ответе: обмен падает, соединение НЕ возвращается в пул
func TestDoTIDMismatch(t *testing.T) {
	clean := "204.8.99.144"
	addr := serveDoTEx(t, &clean, nil, false, true)
	u := dotUpstream(t, addr)
	t.Cleanup(u.closeAll)

	px := &DNSMITMProxy{timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	req, _ := q.Pack()
	if _, err := px.exchangeUpstream(context.Background(), u, req, "udp"); err == nil {
		t.Fatal("чужой ID должен приводить к ошибке")
	}
	if len(u.dot.pool) != 0 {
		t.Fatalf("испорченное соединение вернулось в пул (%d)", len(u.dot.pool))
	}
}

// закрытие пула: Get после Close ошибается (диала нет), Put после Close
// закрывает соединение - send-on-closed-channel невозможен
func TestConnPoolCloseRace(t *testing.T) {
	dialCalled := 0
	p := newConnPoolDial("tcp", "127.0.0.1:1", 2, func(ctx context.Context) (net.Conn, error) {
		dialCalled++
		c1, c2 := net.Pipe()
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = c2.Close()
		}()
		return c1, nil
	})
	p.Close()
	if _, err := p.Get(context.Background()); err == nil {
		t.Fatal("Get после Close должен ошибаться")
	}
	if dialCalled != 0 {
		t.Fatal("после Close диал не должен вызываться")
	}
	c1, c2 := net.Pipe()
	p.Put(c1) // Put после Close закрывает соединение
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("Put после Close должен закрывать соединение (конец увидел EOF)")
	}
	_ = c2.Close()
}
