package dnsMITMProxy

// Бутстрап-резолв имён DoH/DoT-апстримов (rev12). Системный резолвер для
// этого не годится: в /etc/resolv.conf OpenWrt бывает ::1 (dnsmasq слушает
// только 127.0.0.1), а круг «система -> MT -> каскад -> снова нужен
// резолв» замкнут сам на себя (живой кейс 0.42: lookup dns.google on
// [::1]:53: i/o timeout). Имя решается СВОИМ резолвером через plain-
// апстримы каскада (живые вперёд; фолбэк 77.88.8.8; UDP, короткий
// таймаут), ответ кэшируется; диал - по IP, SNI/Host остаются именем
// (сертификат проверяется как раньше, tlsConfigFor не тронут).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// bootstrapFallbackServer - последний шанс, когда в каскаде не осталось
// ни одного живого IP-plain-апстрима (Яндекс: на сети владельца чистый
// по UDP); тесты подменяют его на локальный сервер.
var bootstrapFallbackServer = "77.88.8.8:53"

const (
	bootstrapCacheTTL     = 5 * time.Minute
	bootstrapQueryTimeout = 1500 * time.Millisecond
)

type bootstrapEntry struct {
	ips []net.IP
	at  time.Time
}

// bootstrapResolver - кэширующий резолвер имён DoH/DoT-апстримов.
// serversFunc отдаёт бутстрап-серверы (plain-апстримы менеджера, живые
// вперёд); nil или пусто - только фолбэк. Горячее обновление списка
// апстримов кэш не трогает.
type bootstrapResolver struct {
	mu          sync.Mutex
	cache       map[string]bootstrapEntry
	serversFunc func() []string
	now         func() time.Time // точка подмены в тестах (проверка TTL)
}

func newBootstrapResolver(servers func() []string) *bootstrapResolver {
	return &bootstrapResolver{
		cache:       make(map[string]bootstrapEntry),
		serversFunc: servers,
		now:         time.Now,
	}
}

// dial - диал к host:port с бутстрап-резолвом имени. IP-литерал (и
// nil-резолвер) идёт напрямую, как до rev12; имя диалится по IP.
func (r *bootstrapResolver) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	ips, err := r.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("bootstrap resolve %q: %w", host, err)
	}
	var lastErr error
	for _, ip := range ips {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("bootstrap: %q без адресов", host)
	}
	return nil, lastErr
}

// dialUpstreamHost - диал к апстриму из его адреса: имя решает
// бутстрап-резолвер (диал по IP; SNI/верификация остаются в TLS-конфиге
// вызывающего), IP-литерал и nil-резолвер - напрямую, как до rev12.
func dialUpstreamHost(ctx context.Context, bs *bootstrapResolver, network, addr string) (net.Conn, error) {
	if bs == nil {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return bs.dial(ctx, network, addr)
}

// lookup - имя из кэша (TTL) или свежий резолв; при отказе резолва
// запись живёт ещё один TTL на устаревшем ответе: сеть врёт - DoH/DoT
// по прежнему адресу работают, и каждый запрос не долбит мёртвые
// бутстрап-серверы.
func (r *bootstrapResolver) lookup(ctx context.Context, host string) ([]net.IP, error) {
	now := r.now()
	r.mu.Lock()
	e, cached := r.cache[host]
	r.mu.Unlock()
	if cached && now.Sub(e.at) < bootstrapCacheTTL {
		return e.ips, nil
	}
	ips, err := r.query(ctx, host)
	if err != nil {
		if !cached {
			return nil, err
		}
		r.mu.Lock()
		r.cache[host] = bootstrapEntry{ips: e.ips, at: now}
		r.mu.Unlock()
		log.Debug().Str("host", host).Err(err).Msg("dns bootstrap: stale hit")
		return e.ips, nil
	}
	r.mu.Lock()
	r.cache[host] = bootstrapEntry{ips: ips, at: now}
	r.mu.Unlock()
	log.Debug().Str("host", host).Strs("ips", ipStrings(ips)).Msg("dns bootstrap resolved")
	return ips, nil
}

// query - перебор бутстрап-серверов: plain-апстримы каскада (только
// IP-литералы - имя чужим именем не решается), затем фолбэк.
func (r *bootstrapResolver) query(ctx context.Context, host string) ([]net.IP, error) {
	servers := make([]string, 0, 4)
	if r.serversFunc != nil {
		servers = append(servers, r.serversFunc()...)
	}
	dup := false
	for _, s := range servers {
		if s == bootstrapFallbackServer {
			dup = true
			break
		}
	}
	if !dup {
		servers = append(servers, bootstrapFallbackServer)
	}
	var lastErr error
	for _, srv := range servers {
		ips, err := r.queryServer(ctx, srv, host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("bootstrap: ответы без адресов")
	}
	return nil, lastErr
}

// queryServer - один сервер: A, при пустом успехе AAAA; NXDOMAIN и
// прочие rcode-ошибки - сразу следующий сервер (AAAA там тоже не будет).
func (r *bootstrapResolver) queryServer(ctx context.Context, srv, host string) ([]net.IP, error) {
	ips, err := r.queryType(ctx, srv, host, dns.TypeA)
	if len(ips) > 0 {
		return ips, nil
	}
	if err != nil {
		return nil, err
	}
	ips, err = r.queryType(ctx, srv, host, dns.TypeAAAA)
	if len(ips) > 0 {
		return ips, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("ответ без A/AAAA")
}

func (r *bootstrapResolver) queryType(ctx context.Context, srv, host string, qtype uint16) ([]net.IP, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(host), qtype)
	q.RecursionDesired = true
	req, err := q.Pack()
	if err != nil {
		return nil, err
	}
	// свой короткий таймаут, зажатый бюджетом вызывающего (клиентский
	// запрос делит его между апстримами, канарейка живёт на health.Timeout)
	timeout := bootstrapQueryTimeout
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < timeout {
			timeout = left
		}
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	resp, err := udpExchangeOnce(ctx, srv, q, req, timeout)
	if err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		return nil, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[msg.Rcode])
	}
	var ips []net.IP
	for _, rr := range msg.Answer {
		switch a := rr.(type) {
		case *dns.A:
			if a.A != nil {
				ips = append(ips, a.A)
			}
		case *dns.AAAA:
			if a.AAAA != nil {
				ips = append(ips, a.AAAA)
			}
		}
	}
	return ips, nil
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
