package dnsMITMProxy

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// Зонный DNS (rev13): доменные зоны с СОБСТВЕННЫМИ упорядоченными
// апстримами - запрос, чьё имя попадает в зону, обслуживает менеджер зоны
// (тот же upstreamManager, общий каскад не участвует). Здоровье зонных
// апстримов - liveness (любой валидный ответ, контент не проверяем:
// корпоративный резолвер не обязан знать канарейку deb.torproject.org -
// контент-чек дал бы ложную «подмену» и живой корп-DNS был бы помечен
// мёртвым). Ни один сервер зоны не ответил -> SERVFAIL клиенту
// (fail-closed: имена зоны не утекают в общий каскад); FallbackOpen
// разрешает деградацию в общий список (выбор владельца, не умолчание).

// ZoneRoute - зона для прокси: имя (без точки, регистр нормализуем),
// упорядоченные адреса апстримов (plain host:port / tls:// / https://),
// FallbackOpen - при полном отвале серверов зоны отвечать общим каскадом
// (иначе SERVFAIL).
type ZoneRoute struct {
	Zone          string
	UpstreamAddrs []string
	FallbackOpen  bool
}

// ZoneSnapshot - снимок зоны для мониторинга (API rev13): имя без точки,
// политика отвала и стейт её менеджера (порядок = приоритет).
type ZoneSnapshot struct {
	Zone         string            `json:"zone"`
	FallbackOpen bool              `json:"fallback"`
	Upstreams    UpstreamsSnapshot `json:"upstreams"`
}

type zoneEntry struct {
	suffix       string // fqdn с хвостовой точкой, lowercase ("corp.example.com.")
	mgr          *upstreamManager
	fallbackOpen bool
}

// MaxZones - потолок таблицы зон (редактор mawg ограничен тем же).
const MaxZones = 64

// NormalizeZone - каноническое имя зоны: lowercase, trim, без хвостовых
// точек; "" - кривой ввод (пусто, точка-корень, пустые метки, пробелы,
// схемы, слэши). Зона из одного лейбла ("local") допустима -
// longest-suffix match её честно сузит.
func NormalizeZone(zone string) string {
	z := strings.ToLower(strings.TrimSpace(zone))
	z = strings.TrimRight(z, ".")
	if z == "" {
		return ""
	}
	if strings.ContainsAny(z, " \t/\\") || strings.Contains(z, "://") {
		return ""
	}
	if strings.Contains(z, "..") {
		return ""
	}
	return z
}

// zoneSuffix - fqdn-суффикс зоны для матчинга ("corp.example.com.").
func zoneSuffix(zone string) string {
	if z := NormalizeZone(zone); z != "" {
		return z + "."
	}
	return ""
}

// UpdateZones - горячая подмена таблицы зон (API rev13, SIGHUP/LoadConfig):
// менеджеры выживших зон переиспользуются (update адресов без потери
// здоровья), новые строятся, исчезнувшие закрываются. Liveness-воркер
// зоны включён всегда (Enabled форсится: контент-канарейка к зонам
// неприменима), K/M/RestoreGap - из общей политики.
func (p *DNSMITMProxy) UpdateZones(routes []ZoneRoute, health UpstreamHealth) {
	zh := health
	zh.Enabled = true

	p.zonesMu.Lock()
	defer p.zonesMu.Unlock()

	keep := make(map[string]*upstreamManager, len(p.zones))
	for _, e := range p.zones {
		keep[e.suffix] = e.mgr
	}
	next := make([]zoneEntry, 0, len(routes))
	seen := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		suffix := zoneSuffix(r.Zone)
		if suffix == "" {
			continue
		}
		if _, dup := seen[suffix]; dup {
			continue
		}
		if len(next) >= MaxZones {
			log.Warn().Str("zone", r.Zone).Msg("zone table full, dropping zone")
			break
		}
		seen[suffix] = struct{}{}
		if m, ok := keep[suffix]; ok {
			delete(keep, suffix)
			m.update(r.UpstreamAddrs, zh)
			next = append(next, zoneEntry{suffix: suffix, mgr: m, fallbackOpen: r.FallbackOpen})
			continue
		}
		m := newZoneUpstreamManager(suffix, r.UpstreamAddrs, p.maxIdle, zh)
		if p.healthCtx != nil {
			m.start(p.healthCtx)
		}
		next = append(next, zoneEntry{suffix: suffix, mgr: m, fallbackOpen: r.FallbackOpen})
	}
	for s, m := range keep {
		m.close()
		log.Info().Str("zone", s).Msg("dns zone removed")
	}
	p.zones = next
	log.Info().Int("zones", len(next)).Msg("dns zone table updated")
}

// ZonesSnapshot - снимок таблицы зон (API rev13, GET /api/v1/dns/zones).
func (p *DNSMITMProxy) ZonesSnapshot() []ZoneSnapshot {
	p.zonesMu.RLock()
	defer p.zonesMu.RUnlock()
	out := make([]ZoneSnapshot, 0, len(p.zones))
	for _, e := range p.zones {
		out = append(out, ZoneSnapshot{
			Zone:         strings.TrimSuffix(e.suffix, "."),
			FallbackOpen: e.fallbackOpen,
			Upstreams:    e.mgr.snapshot(),
		})
	}
	return out
}

// zonesCount - есть ли зоны (дешёвая проверка, нужен ли парс запроса).
func (p *DNSMITMProxy) zonesCount() int {
	p.zonesMu.RLock()
	defer p.zonesMu.RUnlock()
	return len(p.zones)
}

// matchZone - longest-suffix матч имени из вопроса: точное равенство или
// имя внутри зоны; побеждает самая длинная зона (corp.example.com бьёт
// example.com). nil - зона не задана для имени.
func (p *DNSMITMProxy) matchZone(qname string) *zoneEntry {
	if len(p.zones) == 0 {
		return nil
	}
	q := strings.ToLower(qname)
	if q == "." {
		return nil
	}
	var best *zoneEntry
	for i := range p.zones {
		e := &p.zones[i]
		if q == e.suffix || strings.HasSuffix(q, "."+e.suffix) {
			if best == nil || len(e.suffix) > len(best.suffix) {
				best = e
			}
		}
	}
	return best
}

// livenessProbe - зонд живости зонного апстрима: A-запрос самого имени
// зоны (корп-DNS обязан отвечать за свою зону); ЛЮБОЙ валидный ответ с
// совпавшим id = жив (NXDOMAIN - тоже ответ). Контент не проверяем.
func livenessProbe(ctx context.Context, u *upstream, name string, timeout time.Duration) (bool, string) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
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
	m := new(dns.Msg)
	if err := m.Unpack(resp); err != nil {
		return false, "unpack: " + err.Error()
	}
	if m.Id != q.Id {
		return false, errAnswerMismatch.Error()
	}
	return true, ""
}
