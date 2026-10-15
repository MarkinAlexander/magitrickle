package dnsMITMProxy

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// Канарейка спуфа (63-док, схема владельца): A deb.torproject.org у
// честного резолвера содержит минимум один адрес канонического набора;
// непустой ответ без набора = подмена (NXDOMAIN-перехват и т.п.).
// Эмпирика Фазы E (63-док): на отравленной сети сервер «жив», но отдаёт
// яд - liveness-фейловер бесполезен, здоровье проверяется КОНТЕНТОМ.
const canaryDomain = "deb.torproject.org"

var canaryIPs = map[string]struct{}{
	"204.8.99.144":    {},
	"204.8.99.146":    {},
	"95.216.163.36":   {},
	"116.202.120.165": {},
	"116.202.120.166": {},
}

// UpstreamHealth - политика зондов апстримов (46-док §3): вниз - K неудач
// ПОДРЯД, вверх - M успехов ПОДРЯД и не чаще раза в RestoreGap (флапы и
// износ флеша давим гистерезисом; стейт только в памяти, в конфиг не пишем).
type UpstreamHealth struct {
	Enabled       bool
	Interval      time.Duration
	Timeout       time.Duration
	FailCycles    uint
	RestoreCycles uint
	RestoreGap    time.Duration
}

type upstream struct {
	addr string
	tcp  *connPool
	udp  *connPool

	mu       sync.Mutex
	alive    bool
	fails    uint
	oks      uint
	lastSwap time.Time
	reason   string
}

func newUpstream(addr string, maxIdle uint) *upstream {
	return &upstream{
		addr:  addr,
		tcp:   newConnPool("tcp", addr, maxIdle),
		udp:   newConnPool("udp", addr, maxIdle),
		alive: true, // приоритетный порядок, пока канарейка не доказала обратное
	}
}

func (u *upstream) isAlive() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.alive
}

// upstreamManager - упорядоченный список апстримов (приоритет = порядок)
// плюс их здоровье. Ноль апстримов недопустим (listening без апстрима
// смысла не имеет - минимум один приходит из legacy upstream).
type upstreamManager struct {
	mu        sync.RWMutex
	upstreams []*upstream
	health    UpstreamHealth
	maxIdle   uint

	workerMu     sync.Mutex
	parent       context.Context
	workerCancel context.CancelFunc
}

func newUpstreamManager(addrs []string, maxIdle uint, h UpstreamHealth) *upstreamManager {
	m := &upstreamManager{maxIdle: maxIdle, health: h}
	m.upstreams = make([]*upstream, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if _, dup := seen[a]; dup {
			continue // дубликат адреса - один апстрим
		}
		seen[a] = struct{}{}
		m.upstreams = append(m.upstreams, newUpstream(a, maxIdle))
	}
	return m
}

// start - запуск воркера зондов (работает при включённой политике и
// >=2 апстримах: с одним переключаться некуда).
func (m *upstreamManager) start(parent context.Context) {
	m.workerMu.Lock()
	m.parent = parent
	m.workerMu.Unlock()

	m.mu.RLock()
	need := m.health.Enabled && len(m.upstreams) >= 2
	m.mu.RUnlock()
	m.respawnWorker(need)
}

func (m *upstreamManager) respawnWorker(need bool) {
	m.workerMu.Lock()
	defer m.workerMu.Unlock()
	if m.workerCancel != nil {
		m.workerCancel()
		m.workerCancel = nil
	}
	if need && m.parent != nil {
		ctx, cancel := context.WithCancel(m.parent)
		m.workerCancel = cancel
		go m.worker(ctx)
	}
}

func (m *upstreamManager) close() {
	m.respawnWorker(false)
	m.mu.Lock()
	ups := m.upstreams
	m.upstreams = nil
	m.mu.Unlock()
	for _, u := range ups {
		u.tcp.Close()
		u.udp.Close()
	}
}

// update - горячая подмена списка апстримов и политики зондов
// (SIGHUP/LoadConfig без рестарта слушателей): выжившие адреса сохраняют
// пулы и состояние здоровья, новые добавляются, исчезнувшие закрываются.
func (m *upstreamManager) update(addrs []string, h UpstreamHealth) {
	m.mu.Lock()
	keep := make(map[string]*upstream, len(m.upstreams))
	for _, u := range m.upstreams {
		keep[u.addr] = u
	}
	next := make([]*upstream, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		if u, ok := keep[a]; ok {
			next = append(next, u)
			delete(keep, a)
		} else {
			next = append(next, newUpstream(a, m.maxIdle))
		}
	}
	for _, u := range keep {
		u.tcp.Close()
		u.udp.Close()
	}
	m.upstreams = next
	m.health = h
	m.mu.Unlock()

	m.respawnWorker(h.Enabled && len(next) >= 2)
	log.Info().
		Strs("upstreams", addrs).
		Bool("health", h.Enabled && len(next) >= 2).
		Msg("dns upstream list updated")
}

// candidates - порядок перебора при клиентском запросе: живые по
// приоритету, затем мёртвые по приоритету (DNS не отказываем целиком -
// деградация по приоритету; канарейка решает, кого отравили).
func (m *upstreamManager) candidates() []*upstream {
	m.mu.RLock()
	defer m.mu.RUnlock()
	live := make([]*upstream, 0, len(m.upstreams))
	dead := make([]*upstream, 0, len(m.upstreams))
	for _, u := range m.upstreams {
		if u.isAlive() {
			live = append(live, u)
		} else {
			dead = append(dead, u)
		}
	}
	return append(live, dead...)
}

func (m *upstreamManager) worker(ctx context.Context) {
	m.mu.RLock()
	interval := m.health.Interval
	m.mu.RUnlock()
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.probeAll(ctx)
		}
	}
}

func (m *upstreamManager) probeAll(ctx context.Context) {
	m.mu.RLock()
	ups := make([]*upstream, len(m.upstreams))
	copy(ups, m.upstreams)
	timeout := m.health.Timeout
	m.mu.RUnlock()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	var wg sync.WaitGroup
	for _, u := range ups {
		wg.Add(1)
		go func(u *upstream) {
			defer wg.Done()
			ok, why := canaryProbe(ctx, u.addr, timeout)
			m.mark(u, ok, why)
		}(u)
	}
	wg.Wait()
}

// mark - цикл зонда одного апстрима: K неудач подряд -> dead, M успехов
// подряд и не чаще раза в RestoreGap -> alive (46-док §3). Успех считается
// ТОЛЬКО чистой канарейкой: отравленный «живой» апстрим не вернётся.
func (m *upstreamManager) mark(u *upstream, ok bool, why string) {
	m.mu.RLock()
	h := m.health
	m.mu.RUnlock()
	now := time.Now()

	u.mu.Lock()
	defer u.mu.Unlock()
	if ok {
		u.fails = 0
		u.oks++
		if !u.alive && h.RestoreCycles > 0 && u.oks >= h.RestoreCycles && now.Sub(u.lastSwap) >= h.RestoreGap {
			u.alive = true
			u.oks = 0
			u.lastSwap = now
			u.reason = ""
			log.Info().Str("upstream", u.addr).Msg("dns upstream restored (canary clean)")
		}
		return
	}
	u.oks = 0
	u.fails++
	if u.alive && h.FailCycles > 0 && u.fails >= h.FailCycles {
		u.alive = false
		u.fails = 0
		u.lastSwap = now
		u.reason = why
		log.Warn().Str("upstream", u.addr).Str("reason", why).Msg("dns upstream marked dead (canary)")
	}
}

// markTransportError - ошибка реального клиентского запроса: тоже цикл
// «болен» (мёртвый под нагрузкой помечается быстрее воркера); возврат -
// только по канарейке.
func (m *upstreamManager) markTransportError(u *upstream) {
	m.mark(u, false, "transport error")
}

// canaryProbe - A-запрос канарейки напрямую в апстрим (мимо пулов, своё
// соединение со своим таймаутом); true = в ответе есть канонический адрес.
func canaryProbe(ctx context.Context, addr string, timeout time.Duration) (bool, string) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(canaryDomain), dns.TypeA)
	req, err := q.Pack()
	if err != nil {
		return false, "pack: " + err.Error()
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "udp", addr)
	if err != nil {
		return false, "dial: " + err.Error()
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write(req); err != nil {
		return false, "write: " + err.Error()
	}
	buf := make([]byte, dns.MaxMsgSize)
	// до двух чтений: возможен чужой/запоздалый ответ с другим id
	for attempt := 0; attempt < 2; attempt++ {
		n, err := conn.Read(buf)
		if err != nil {
			return false, "read: " + err.Error()
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil || msg.Id != q.Id {
			continue
		}
		if msg.Rcode != dns.RcodeSuccess {
			return false, "rcode " + dns.RcodeToString[msg.Rcode]
		}
		answers := 0
		for _, rr := range msg.Answer {
			if a, ok := rr.(*dns.A); ok {
				answers++
				if _, hit := canaryIPs[a.A.String()]; hit {
					return true, ""
				}
			}
		}
		if answers == 0 {
			return false, "пустой ответ (NXDOMAIN-перехват?)"
		}
		return false, "подмена: канонических адресов нет"
	}
	return false, "ответ без совпадения id"
}
