package dnsMITMProxy

import (
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// Статические hosts (rev21): имя -> адреса; запрос имени из таблицы
// отвечает сам dns-proxy, БЕЗ апстримов и БЕЗ response-hook - то есть
// AAAA-фильтр (DisableDropAAAA) на статические записи не действует: пин
// пользователя сознательный, его v6 не должен теряться (живой кейс
// ntc.party: публичного A нет вовсе, адрес живёт только в записи).
// Таблицу наполняет контроллер (mawg): свой список + /etc/hosts OpenWrt
// + ip host Keenetic - всё, что роутер и владелец знают локально.

// HostPair - пара имя/адрес для загрузки таблицы (API и старт).
type HostPair struct {
	Name    string
	Address string
}

const staticHostTTL = 300

// maxStaticHosts - потолок таблицы (редактор mawg ограничен тем же).
const MaxStaticHosts = 512

// NormalizeHostName - каноническое имя записи: lowercase, trim, без
// хвостовых точек; "" - кривой ввод.
func NormalizeHostName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimRight(n, ".")
	if n == "" || strings.ContainsAny(n, " \t/\\") || strings.Contains(n, "..") {
		return ""
	}
	return n
}

// UpdateHosts - горячая замена таблицы статических hosts (старт, SIGHUP
// не нужен - API контроллера); кривые пары молча пропускаются.
func (p *DNSMITMProxy) UpdateHosts(pairs []HostPair) {
	m := make(map[string][]net.IP, len(pairs))
	for _, h := range pairs {
		name := NormalizeHostName(h.Name)
		if name == "" {
			continue
		}
		ip := net.ParseIP(h.Address)
		if ip == nil {
			continue
		}
		m[name] = append(m[name], ip)
	}
	p.hostsMu.Lock()
	p.hosts = m
	p.hostsMu.Unlock()
	log.Info().Int("hosts", len(m)).Msg("static hosts updated")
}

// HostsSnapshot - таблица для API GET (пары имя->адрес, стабильный
// порядок по имени и адресу).
func (p *DNSMITMProxy) HostsSnapshot() []HostPair {
	p.hostsMu.RLock()
	defer p.hostsMu.RUnlock()
	out := make([]HostPair, 0, len(p.hosts))
	for name, ips := range p.hosts {
		for _, ip := range ips {
			out = append(out, HostPair{Name: name, Address: ip.String()})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Address < out[j].Address
	})
	return out
}

// hostsCount - нужно ли распаковывать запрос (процессReq).
func (p *DNSMITMProxy) hostsCount() int {
	p.hostsMu.RLock()
	defer p.hostsMu.RUnlock()
	return len(p.hosts)
}

// staticHostsResponse - ответ из таблицы: имя найдено -> NOERROR с
// записями запрошенного типа (A/AAAA); адресов семьи нет -> NODATA
// (пустой NOERROR); имя не найдено -> nil (дальше по зонам/каскаду).
func (p *DNSMITMProxy) staticHostsResponse(reqMsg *dns.Msg) *dns.Msg {
	if len(reqMsg.Question) == 0 {
		return nil
	}
	q := reqMsg.Question[0]
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return nil
	}
	p.hostsMu.RLock()
	// q.Name у miekg/dns с хвостовой точкой - нормализуем так же, как ключи таблицы
	ips, ok := p.hosts[NormalizeHostName(q.Name)]
	p.hostsMu.RUnlock()
	if !ok {
		return nil
	}
	resp := new(dns.Msg)
	resp.SetReply(reqMsg)
	resp.Compress = true
	want4 := q.Qtype == dns.TypeA
	for _, ip := range ips {
		if want4 && ip.To4() != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: staticHostTTL},
				A:   ip,
			})
		}
		if !want4 && ip.To4() == nil {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: staticHostTTL},
				AAAA: ip,
			})
		}
	}
	return resp
}
