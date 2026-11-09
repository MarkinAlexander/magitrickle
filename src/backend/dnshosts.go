package magitrickle

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"magitrickle/app"
	"magitrickle/models"
	"magitrickle/utils/dnsMITMProxy"

	"github.com/rs/zerolog/log"
)

// normalizeHostPair - канонизация записи: имя lowercase без точки,
// адрес - валидный IP. Дубликаты (имя+адрес) схлопываются.
func normalizeHostPair(h models.AppConfigDNSProxyHost) (models.AppConfigDNSProxyHost, bool) {
	name := strings.ToLower(strings.TrimSpace(h.Name))
	name = strings.TrimRight(name, ".")
	if name == "" || strings.ContainsAny(name, " \t/\\") || strings.Contains(name, "..") {
		return models.AppConfigDNSProxyHost{}, false
	}
	ip := net.ParseIP(strings.TrimSpace(h.Address))
	if ip == nil {
		return models.AppConfigDNSProxyHost{}, false
	}
	return models.AppConfigDNSProxyHost{Name: name, Address: ip.String()}, true
}

// normalizeHosts - вся таблица: валидация, дедуп, стабильный порядок.
func normalizeHosts(hosts []models.AppConfigDNSProxyHost) ([]models.AppConfigDNSProxyHost, error) {
	if len(hosts) > dnsMITMProxy.MaxStaticHosts {
		return nil, fmt.Errorf("%w: записей больше %d", app.ErrDnsHostsInvalid, dnsMITMProxy.MaxStaticHosts)
	}
	out := make([]models.AppConfigDNSProxyHost, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		norm, ok := normalizeHostPair(h)
		if !ok {
			return nil, fmt.Errorf("%w: запись %q -> %q", app.ErrDnsHostsInvalid, h.Name, h.Address)
		}
		key := norm.Name + "/" + norm.Address
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, norm)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Address < out[j].Address
	})
	return out, nil
}

// SetDnsHosts - замена таблицы статических hosts (rev21): модель ->
// прокси горячо (ответ сам, мимо апстримов и AAAA-фильтра) + SaveConfig.
func (a *App) SetDnsHosts(hosts []models.AppConfigDNSProxyHost) error {
	norm, err := normalizeHosts(hosts)
	if err != nil {
		return err
	}
	a.stateMu.Lock()
	a.config.DNSProxy.Hosts = norm
	a.stateMu.Unlock()
	if err := a.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	if a.dnsMITM != nil {
		a.dnsMITM.UpdateHosts(hostsToPairs(norm))
	}
	log.Info().Int("hosts", len(norm)).Msg("dns hosts updated via api")
	return nil
}

// hostsToPairs - модель -> пары прокси.
func hostsToPairs(hosts []models.AppConfigDNSProxyHost) []dnsMITMProxy.HostPair {
	out := make([]dnsMITMProxy.HostPair, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, dnsMITMProxy.HostPair{Name: h.Name, Address: h.Address})
	}
	return out
}

// DnsHostsSnapshot - состояние таблицы статических hosts (API rev21);
// ok=false, если dns-proxy ещё не построен (до Start).
func (a *App) DnsHostsSnapshot() ([]dnsMITMProxy.HostPair, bool) {
	if a.dnsMITM == nil {
		return nil, false
	}
	return a.dnsMITM.HostsSnapshot(), true
}
