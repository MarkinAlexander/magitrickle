package magitrickle

import (
	"fmt"

	"magitrickle/app"
	"magitrickle/models"
	"magitrickle/utils/dnsMITMProxy"

	"github.com/rs/zerolog/log"
)

// normalizeZoneName - канонизация имени зоны для модели: lowercase,
// trim, без хвостовой точки; "" - кривой ввод.
func normalizeZoneName(zone string) string {
	return dnsMITMProxy.NormalizeZone(zone)
}

// normalizeZones - валидация+канонизация таблицы зон из редактора (API
// rev13): зона обязательна и кривая -> ErrDnsZonesInvalid; апстримы зоны
// обязательны (сырые адреса из Address разбираются parseUpstreamAddrs);
// дубли зон схлопываются; пустой список = очистка (легален).
func normalizeZones(zones []models.AppConfigDNSProxyZone) ([]models.AppConfigDNSProxyZone, error) {
	if len(zones) > dnsMITMProxy.MaxZones {
		return nil, fmt.Errorf("%w: зон больше %d", app.ErrDnsZonesInvalid, dnsMITMProxy.MaxZones)
	}
	out := make([]models.AppConfigDNSProxyZone, 0, len(zones))
	seen := make(map[string]struct{}, len(zones))
	for _, z := range zones {
		name := normalizeZoneName(z.Zone)
		if name == "" {
			return nil, fmt.Errorf("%w: кривое имя зоны %q", app.ErrDnsZonesInvalid, z.Zone)
		}
		addrs := make([]string, 0, len(z.Upstreams))
		for _, u := range z.Upstreams {
			addrs = append(addrs, u.Address)
		}
		ups, err := parseUpstreamAddrs(addrs)
		if err != nil {
			return nil, fmt.Errorf("%w: зона %q: %v", app.ErrDnsZonesInvalid, name, err)
		}
		if _, dup := seen[name]; dup {
			continue // дубль зоны - одна запись (первая)
		}
		seen[name] = struct{}{}
		out = append(out, models.AppConfigDNSProxyZone{Zone: name, Upstreams: ups, FallbackOpen: z.FallbackOpen})
	}
	return out, nil
}

// SetDnsZones - замена таблицы зон (API rev13, редактор mawg): валидация,
// персистентная запись конфига, горячая подмена живому dns-proxy без
// рестарта демона. Пустой список = очистка зон. Общий каскад не трогается.
func (a *App) SetDnsZones(zones []models.AppConfigDNSProxyZone) error {
	norm, err := normalizeZones(zones)
	if err != nil {
		return err
	}
	a.stateMu.Lock()
	a.config.DNSProxy.Zones = norm
	a.stateMu.Unlock()
	if err := a.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	if a.dnsMITM != nil {
		a.dnsMITM.UpdateZones(dnsZoneRoutes(a.config.DNSProxy), dnsHealthConfig(a.config.DNSProxy.Health))
	}
	log.Info().Int("zones", len(norm)).Msg("dns zones updated via api")
	return nil
}

// DnsZonesSnapshot - состояние таблицы зон dns-proxy (API rev13);
// ok=false, если dns-proxy ещё не построен (до Start).
func (a *App) DnsZonesSnapshot() ([]dnsMITMProxy.ZoneSnapshot, bool) {
	if a.dnsMITM == nil {
		return nil, false
	}
	return a.dnsMITM.ZonesSnapshot(), true
}
