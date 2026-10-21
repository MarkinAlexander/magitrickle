package dnsMITMProxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
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
	kind upKind
	tcp  *connPool // plain: TCP
	udp  *connPool // plain: UDP
	dot  *connPool // DoT: TCP + TLS (кастомный диал)
	dotDialAddr string
	dotTLS      *tls.Config
	doh         *http.Client // DoH: keep-alive внутри транспорта
	dohURL      *url.URL
	bs          *bootstrapResolver // бутстрап-резолв имени (DoT/DoH), nil = системный диал

	mu       sync.Mutex
	alive    bool
	fails    uint
	oks      uint
	lastSwap time.Time
	reason   string
}

// UpstreamState - снимок здоровья одного апстрима для мониторинга (API
// rev8, читает контроллер mawg): alive/active, счётчики подряд, момент и
// причина последнего переключения.
type UpstreamState struct {
	Address  string    `json:"address"`
	Alive    bool      `json:"alive"`
	Active   bool      `json:"active"`
	Fails    uint      `json:"fails"`
	Oks      uint      `json:"oks"`
	LastSwap time.Time `json:"lastSwap"`
	Reason   string    `json:"reason,omitempty"`
}

// UpstreamsSnapshot - снимок состояния менеджера апстримов (API rev8):
// порядок = приоритет, Active - первый живой (клиентские запросы идут в
// него в первую очередь). Стейт только в памяти - снимок честно показывает
// текущее положение, а не историю.
type UpstreamsSnapshot struct {
	Health    UpstreamHealth  `json:"health"`
	Upstreams []UpstreamState `json:"upstreams"`
}

func newUpstream(addr string, maxIdle uint, tlsOverride *tls.Config, bs *bootstrapResolver) *upstream {
	p, err := ParseUpstreamAddr(addr)
	if err != nil {
		// сюда приходят только провалидированные адреса; битый считаем
		// plain - зонд честно пометит его мёртвым, ронять прокси нельзя
		return &upstream{addr: addr, kind: upPlain, alive: true,
			tcp: newConnPool("tcp", addr, maxIdle), udp: newConnPool("udp", addr, maxIdle)}
	}
	return newUpstreamParsed(p, maxIdle, tlsOverride, bs)
}

// newUpstreamParsed - сборка апстрима по разобранному адресу; tlsOverride
// подменяет TLS-конфиг в тестах (самоподписанные серверы), bs решает имена
// хостов DoT/DoH бутстрап-резолвом (nil - системный диалер, как до rev12).
func newUpstreamParsed(p parsedUpstream, maxIdle uint, tlsOverride *tls.Config, bs *bootstrapResolver) *upstream {
	u := &upstream{addr: p.addr, kind: p.kind, alive: true, bs: bs}
	switch p.kind {
	case upDoT:
		u.dotDialAddr = p.dialAddr
		u.dotTLS = tlsConfigFor(p, tlsOverride)
		conf := u.dotTLS
		u.dot = newConnPoolDial("tcp", p.dialAddr, maxIdle, func(ctx context.Context) (net.Conn, error) {
			raw, err := dialUpstreamHost(ctx, bs, "tcp", p.dialAddr)
			if err != nil {
				return nil, err
			}
			c := tls.Client(raw, conf.Clone())
			if deadline, ok := ctx.Deadline(); ok {
				_ = c.SetDeadline(deadline)
			}
			if err := c.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return c, nil
		})
	case upDoH:
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// хост из dohURL: диал по бутстрап-IP, SNI/Host и верификация
				// серта остаются по имени (TLSClientConfig не тронут)
				return dialUpstreamHost(ctx, bs, network, addr)
			},
			TLSClientConfig:     tlsConfigFor(p, tlsOverride).Clone(),
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: int(maxIdle),
			IdleConnTimeout:     90 * time.Second,
		}
		u.doh = &http.Client{Transport: transport}
		u.dohURL = p.dohURL
	default:
		u.tcp = newConnPool("tcp", p.addr, maxIdle)
		u.udp = newConnPool("udp", p.addr, maxIdle)
	}
	return u
}

// closeAll освобождает ресурсы апстрима (вызывается менеджером).
func (u *upstream) closeAll() {
	if u.tcp != nil {
		u.tcp.Close()
	}
	if u.udp != nil {
		u.udp.Close()
	}
	if u.dot != nil {
		u.dot.Close()
	}
	if u.doh != nil {
		u.doh.CloseIdleConnections()
	}
}

func (u *upstream) isAlive() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.alive
}

// state - снимок здоровья одного апстрима (локи менеджера и апстрима не
// вкладываются: snapshot() сначала снимает RLock менеджера).
func (u *upstream) state() UpstreamState {
	u.mu.Lock()
	defer u.mu.Unlock()
	return UpstreamState{
		Address:  u.addr,
		Alive:    u.alive,
		Fails:    u.fails,
		Oks:      u.oks,
		LastSwap: u.lastSwap,
		Reason:   u.reason,
	}
}

// upstreamManager - упорядоченный список апстримов (приоритет = порядок)
// плюс их здоровье. Ноль апстримов недопустим (listening без апстрима
// смысла не имеет - минимум один приходит из legacy upstream).
type upstreamManager struct {
	mu        sync.RWMutex
	upstreams []*upstream
	health    UpstreamHealth
	maxIdle   uint
	// tlsOverride - подмена TLS-конфига апстримов (тесты: локальные
	// самоподписанные серверы); в проде nil.
	tlsOverride *tls.Config
	// bs - бутстрап-резолв имён DoH/DoT-апстримов (rev12) через plain-
	// апстримы этого же списка; живёт вместе с менеджером, кэш переживает
	// горячее обновление списка.
	bs *bootstrapResolver
	// probeName - непустой только у ЗОННЫХ менеджеров (rev13): зонд
	// liveness A-запросом самого имени зоны (любой валидный ответ = жив);
	// пустой = общий каскад с канарейкой-контент-чеком.
	probeName string

	workerMu     sync.Mutex
	parent       context.Context
	workerCancel context.CancelFunc
}

func newUpstreamManager(addrs []string, maxIdle uint, h UpstreamHealth) *upstreamManager {
	m := &upstreamManager{maxIdle: maxIdle, health: h}
	m.bs = newBootstrapResolver(m.bootstrapServers)
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
		m.upstreams = append(m.upstreams, newUpstream(a, m.maxIdle, m.tlsOverride, m.bs))
	}
	return m
}

// newZoneUpstreamManager - менеджер зоны (rev13): та же машина перебора
// и здоровья, но зонд - liveness A-запросом имени зоны (контент-канарейка
// к корпоративному резолверу неприменима).
func newZoneUpstreamManager(suffix string, addrs []string, maxIdle uint, h UpstreamHealth) *upstreamManager {
	m := newUpstreamManager(addrs, maxIdle, h)
	m.probeName = strings.TrimSuffix(suffix, ".")
	return m
}

// bootstrapServers - plain-апстримы каскада для бутстрап-резолва, живые
// вперёд (порядок candidates()); только IP-литералы - plain с именем
// резолвить нечем (цикл), его бутстрап пропускает.
func (m *upstreamManager) bootstrapServers() []string {
	out := make([]string, 0, 2)
	for _, u := range m.candidates() {
		if u.kind != upPlain {
			continue
		}
		host, _, err := net.SplitHostPort(u.addr)
		if err != nil || net.ParseIP(host) == nil {
			continue
		}
		out = append(out, u.addr)
	}
	return out
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
		u.closeAll()
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
			next = append(next, newUpstream(a, m.maxIdle, m.tlsOverride, m.bs))
		}
	}
	for _, u := range keep {
		u.closeAll()
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

// snapshot - снимок стейта для мониторинга (API rev8): порядок апстримов
// сохраняется, Active ставится первому живому (равно candidates()[0]).
func (m *upstreamManager) snapshot() UpstreamsSnapshot {
	m.mu.RLock()
	h := m.health
	ups := make([]*upstream, len(m.upstreams))
	copy(ups, m.upstreams)
	m.mu.RUnlock()

	snap := UpstreamsSnapshot{Health: h, Upstreams: make([]UpstreamState, 0, len(ups))}
	activeSet := false
	for _, u := range ups {
		st := u.state()
		if !activeSet && st.Alive {
			st.Active = true
			activeSet = true
		}
		snap.Upstreams = append(snap.Upstreams, st)
	}
	return snap
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
	probeName := m.probeName
	m.mu.RUnlock()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	var wg sync.WaitGroup
	for _, u := range ups {
		wg.Add(1)
		go func(u *upstream) {
			defer wg.Done()
			var ok bool
			var why string
			if probeName != "" {
				ok, why = livenessProbe(ctx, u, probeName, timeout)
			} else {
				ok, why = canaryProbe(ctx, u, timeout)
			}
			m.mark(u, ok, why)
		}(u)
	}
	wg.Wait()
}

// mark - цикл зонда одного апстрима: K неудач подряд -> dead, M успехов
// подряд и не чаще раза в RestoreGap -> alive (46-док §3). Успех - чистая
// канарейка (общий каскад) или любой валидный ответ (зоны, liveness):
// отравленный «живой» апстрим общего каскада не вернётся.
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
			log.Info().Str("upstream", u.addr).Msg("dns upstream restored (probe clean)")
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
		log.Warn().Str("upstream", u.addr).Str("reason", why).Msg("dns upstream marked dead (probe)")
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
// DoT/DoH зондируются своим транспортом - канал клиента и канал зонда
// должны совпадать, иначе канарейка не видит подмену на пути.
func canaryProbe(ctx context.Context, u *upstream, timeout time.Duration) (bool, string) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(canaryDomain), dns.TypeA)
	req, err := q.Pack()
	if err != nil {
		return false, "pack: " + err.Error()
	}
	var resp []byte
	switch u.kind {
	case upDoH:
		resp, err = dohExchange(ctx, u, req, timeout)
	case upDoT:
		resp, err = dotExchangeOnce(ctx, u, req, timeout)
	default:
		resp, err = udpExchangeOnce(ctx, u.addr, q, req, timeout)
	}
	if err != nil {
		return false, u.kind.String() + ": " + err.Error()
	}
	return canaryCheck(q.Id, resp)
}

// udpExchangeOnce - одиночный UDP-обмен (plain-зонд, как было до DoT/DoH).
func udpExchangeOnce(ctx context.Context, addr string, q *dns.Msg, req []byte, timeout time.Duration) ([]byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, dns.MaxMsgSize)
	// до двух чтений: возможен чужой/запоздалый ответ с другим id
	for attempt := 0; attempt < 2; attempt++ {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil || msg.Id != q.Id {
			continue
		}
		return buf[:n], nil
	}
	return nil, errAnswerMismatch
}

var errAnswerMismatch = errors.New("ответ без совпадения id")

// canaryCheck - проверка ответа канарейки: rcode, непустота и наличие
// канонического адреса (63-док: живой, но отравленный - не «жив»).
func canaryCheck(qid uint16, resp []byte) (bool, string) {
	msg := new(dns.Msg)
	if err := msg.Unpack(resp); err != nil {
		return false, "unpack: " + err.Error()
	}
	if msg.Id != qid {
		return false, errAnswerMismatch.Error()
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
