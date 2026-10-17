package magitrickle

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"magitrickle/app"
	"magitrickle/models"
	"magitrickle/utils/dnsMITMProxy"

	"github.com/rs/zerolog/log"
)

// parseUpstreamAddrs - "8.8.8.8" / "8.8.8.8:5353" / "tls://1.1.1.1[:853]" /
// "https://dns.google[:443][/dns-query]" -> модель сервера. Для схем Address
// хранит полный канонический URI (порт и путь внутри), порт дублируется в
// Port для порядка модели; дубликаты схлопываются по канонической строке.
// app.ErrDnsUpstreamsInvalid - список пуст или адрес кривой.
func parseUpstreamAddrs(addrs []string) ([]models.AppConfigDNSProxyServer, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: список пуст", app.ErrDnsUpstreamsInvalid)
	}
	ups := make([]models.AppConfigDNSProxyServer, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, raw := range addrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil, fmt.Errorf("%w: пустой адрес в списке", app.ErrDnsUpstreamsInvalid)
		}
		if strings.Contains(raw, "://") {
			pu, err := dnsMITMProxy.ParseUpstreamAddr(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", app.ErrDnsUpstreamsInvalid, err)
			}
			if _, dup := seen[pu.Addr()]; dup {
				continue
			}
			seen[pu.Addr()] = struct{}{}
			ups = append(ups, models.AppConfigDNSProxyServer{Address: pu.Addr(), Port: pu.Port()})
			continue
		}
		address, portStr := raw, "53"
		if host, port, err := net.SplitHostPort(raw); err == nil {
			address, portStr = host, port
		}
		address = strings.Trim(address, "[]")
		if address == "" {
			return nil, fmt.Errorf("%w: нет адреса в %q", app.ErrDnsUpstreamsInvalid, raw)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("%w: порт в %q: %v", app.ErrDnsUpstreamsInvalid, raw, err)
		}
		key := net.JoinHostPort(address, portStr)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		ups = append(ups, models.AppConfigDNSProxyServer{Address: address, Port: uint16(port)})
	}
	return ups, nil
}

// DnsUpstreamsSnapshot - состояние апстримов dns-proxy для мониторинга
// (API rev8); ok=false, если dns-proxy ещё не построен (до Start).
func (a *App) DnsUpstreamsSnapshot() (dnsMITMProxy.UpstreamsSnapshot, bool) {
	if a.dnsMITM == nil {
		return dnsMITMProxy.UpstreamsSnapshot{}, false
	}
	return a.dnsMITM.UpstreamsSnapshot(), true
}

// SetDnsUpstreams - замена списка апстримов dns-proxy (API rev8, редактор
// каскада в mawg): валидация, персистентная запись конфига, горячая
// подмена живому менеджеру без рестарта демона (та же механика, что у
// SIGHUP). Одиночный legacy Upstream не трогается - остаётся фолбэком,
// если список когда-нибудь уберут.
func (a *App) SetDnsUpstreams(addrs []string) error {
	ups, err := parseUpstreamAddrs(addrs)
	if err != nil {
		return err
	}
	a.stateMu.Lock()
	a.config.DNSProxy.Upstreams = ups
	a.stateMu.Unlock()
	if err := a.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	if a.dnsMITM != nil {
		a.dnsMITM.UpdateUpstreams(dnsUpstreamAddrs(a.config.DNSProxy), dnsHealthConfig(a.config.DNSProxy.Health))
	}
	log.Info().
		Strs("upstreams", dnsUpstreamAddrs(a.config.DNSProxy)).
		Msg("dns upstreams updated via api")
	return nil
}
