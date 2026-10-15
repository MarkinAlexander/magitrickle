package magitrickle

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"magitrickle/config"
	"magitrickle/constant"
	"magitrickle/models"

	"github.com/dlclark/regexp2"
	"github.com/rs/zerolog/log"
	"go.yaml.in/yaml/v2"
)

var colorRegExp = regexp2.MustCompile(`^#[0-9a-f]{6}$`, regexp2.IgnoreCase)

// upstreamsToFile - список апстримов для файла конфига; nil (ключ не
// задан) сохраняется как nil - только явно заданный список переживает
// запись (пустой список = сознательный возврат на одиночный Upstream).
func upstreamsToFile(ups []models.AppConfigDNSProxyServer) *[]config.DNSProxyServer {
	if ups == nil {
		return nil
	}
	out := make([]config.DNSProxyServer, 0, len(ups))
	for _, u := range ups {
		addr, port := u.Address, u.Port
		out = append(out, config.DNSProxyServer{Address: &addr, Port: &port})
	}
	return &out
}

const cfgFolderLocation = constant.AppStateDir
const cfgFileLocation = cfgFolderLocation + "/config.yaml"

func applyIfSet[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

func (a *App) LoadConfig() error {
	cfgFile, err := os.ReadFile(cfgFileLocation)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}
	cfg := config.Config{}
	err = yaml.Unmarshal(cfgFile, &cfg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	if !strings.HasPrefix(cfg.ConfigVersion, "0.") {
		return ErrConfigUnsupportedVersion
	}

	if cfg.App != nil {
		if cfg.App.HTTPWeb != nil {
			applyIfSet(&a.config.HTTPWeb.Enabled, cfg.App.HTTPWeb.Enabled)
			applyIfSet(&a.config.HTTPWeb.Skin, cfg.App.HTTPWeb.Skin)
			if cfg.App.HTTPWeb.Host != nil {
				applyIfSet(&a.config.HTTPWeb.Host.Address, cfg.App.HTTPWeb.Host.Address)
				applyIfSet(&a.config.HTTPWeb.Host.Port, cfg.App.HTTPWeb.Host.Port)
			}
			if cfg.App.HTTPWeb.Auth != nil {
				applyIfSet(&a.config.HTTPWeb.Auth.Enabled, cfg.App.HTTPWeb.Auth.Enabled)
			}
		}

		if cfg.App.DNSProxy != nil {
			if cfg.App.DNSProxy.Upstream != nil {
				applyIfSet(&a.config.DNSProxy.Upstream.Address, cfg.App.DNSProxy.Upstream.Address)
				applyIfSet(&a.config.DNSProxy.Upstream.Port, cfg.App.DNSProxy.Upstream.Port)
			}
			if cfg.App.DNSProxy.Upstreams != nil {
				ups := make([]models.AppConfigDNSProxyServer, 0, len(*cfg.App.DNSProxy.Upstreams))
				for _, u := range *cfg.App.DNSProxy.Upstreams {
					s := models.AppConfigDNSProxyServer{}
					applyIfSet(&s.Address, u.Address)
					applyIfSet(&s.Port, u.Port)
					ups = append(ups, s)
				}
				a.config.DNSProxy.Upstreams = ups
			}
			if cfg.App.DNSProxy.Health != nil {
				applyIfSet(&a.config.DNSProxy.Health.Enabled, cfg.App.DNSProxy.Health.Enabled)
				applyIfSet(&a.config.DNSProxy.Health.Interval, cfg.App.DNSProxy.Health.Interval)
				applyIfSet(&a.config.DNSProxy.Health.Timeout, cfg.App.DNSProxy.Health.Timeout)
				applyIfSet(&a.config.DNSProxy.Health.FailCycles, cfg.App.DNSProxy.Health.FailCycles)
				applyIfSet(&a.config.DNSProxy.Health.RestoreCycles, cfg.App.DNSProxy.Health.RestoreCycles)
				applyIfSet(&a.config.DNSProxy.Health.RestoreGap, cfg.App.DNSProxy.Health.RestoreGap)
			}
			if cfg.App.DNSProxy.Host != nil {
				applyIfSet(&a.config.DNSProxy.Host.Address, cfg.App.DNSProxy.Host.Address)
				applyIfSet(&a.config.DNSProxy.Host.Port, cfg.App.DNSProxy.Host.Port)
			}
			applyIfSet(&a.config.DNSProxy.DisableRemap53, cfg.App.DNSProxy.DisableRemap53)
			applyIfSet(&a.config.DNSProxy.DisableFakePTR, cfg.App.DNSProxy.DisableFakePTR)
			applyIfSet(&a.config.DNSProxy.DisableDropAAAA, cfg.App.DNSProxy.DisableDropAAAA)
			applyIfSet(&a.config.DNSProxy.MaxIdleConns, cfg.App.DNSProxy.MaxIdleConns)
			applyIfSet(&a.config.DNSProxy.MaxConcurrent, cfg.App.DNSProxy.MaxConcurrent)
			if cfg.App.DNSProxy.Timeout != nil {
				// TODO: Remove this align to milliseconds before release 1.0.0
				t := *cfg.App.DNSProxy.Timeout
				if t < time.Millisecond {
					t *= time.Millisecond
				}
				a.config.DNSProxy.Timeout = t
			}
		}

		if cfg.App.Netfilter != nil {
			if cfg.App.Netfilter.IPTables != nil {
				applyIfSet(&a.config.Netfilter.IPTables.ChainPrefix, cfg.App.Netfilter.IPTables.ChainPrefix)
			}
			if cfg.App.Netfilter.IPSet != nil {
				applyIfSet(&a.config.Netfilter.IPSet.TablePrefix, cfg.App.Netfilter.IPSet.TablePrefix)
				if cfg.App.Netfilter.IPSet.AdditionalTTL != nil {
					// TODO: Remove this align to seconds before release 1.0.0
					t := *cfg.App.Netfilter.IPSet.AdditionalTTL
					if t < time.Second {
						t *= time.Second
					}
					a.config.Netfilter.IPSet.AdditionalTTL = t
				}
			}
			applyIfSet(&a.config.Netfilter.DisableIPv4, cfg.App.Netfilter.DisableIPv4)
			applyIfSet(&a.config.Netfilter.DisableIPv6, cfg.App.Netfilter.DisableIPv6)
			applyIfSet(&a.config.Netfilter.StartMarkTableIndex, cfg.App.Netfilter.StartMarkTableIndex)
		}

		applyIfSet(&a.config.Link, cfg.App.Link)
		applyIfSet(&a.config.ShowAllInterfaces, cfg.App.ShowAllInterfaces)
		applyIfSet(&a.config.LogLevel, cfg.App.LogLevel)
	}

	// горячая подмена апстримов живому dns-proxy (SIGHUP без рестарта
	// демона; до Start() a.dnsMITM == nil - подменять нечего)
	if a.dnsMITM != nil {
		a.dnsMITM.UpdateUpstreams(dnsUpstreamAddrs(a.config.DNSProxy), dnsHealthConfig(a.config.DNSProxy.Health))
	}

	a.subscriptionSyncMu.Lock()
	defer a.subscriptionSyncMu.Unlock()

	a.stateMu.Lock()
	defer a.stateMu.Unlock()

	if cfg.Groups != nil {
		// отключаем старые группы и очищаем срез
		for _, group := range a.userRuleSets {
			_ = group.Disable()
		}
		a.userRuleSets = a.userRuleSets[:0]

		for _, group := range *cfg.Groups {
			if match, _ := colorRegExp.MatchString(group.Color); !match {
				group.Color = "#ffffff"
			} else {
				group.Color = strings.ToLower(group.Color)
			}
			// источники: выкидываем непарсящиеся записи (конфиг могли
			// править руками), валидные оставляем как есть
			sources := group.Sources[:0]
			for _, src := range group.Sources {
				src = strings.TrimSpace(src)
				if src == "" {
					continue
				}
				if _, _, err := net.ParseCIDR(src); err != nil && net.ParseIP(src) == nil {
					log.Warn().Str("group", group.Name).Str("source", src).Msg("dropping invalid group source from config")
					continue
				}
				sources = append(sources, src)
			}
			group.Sources = sources
			if err := a.addGroupLocked(group); err != nil {
				return err
			}
		}
	}

	if cfg.Subscriptions != nil {
		a.subscriptions = append(a.subscriptions[:0], *cfg.Subscriptions...)
	} else {
		a.subscriptions = a.subscriptions[:0]
	}

	return a.syncSubscriptionRuleSetsLocked()
}

func (a *App) SaveConfig() error {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()

	groups := make([]*models.Group, 0, len(a.userRuleSets))
	for _, rs := range a.userRuleSets {
		if gm := rs.Model(); gm != nil {
			groups = append(groups, gm)
		}
	}

	cfg := config.Config{
		ConfigVersion: constant.Version,
		App: &config.App{
			HTTPWeb: &config.HTTPWeb{
				Enabled: &a.config.HTTPWeb.Enabled,
				Auth: &config.Auth{
					Enabled: &a.config.HTTPWeb.Auth.Enabled,
				},
				Host: &config.HTTPWebServer{
					Address: &a.config.HTTPWeb.Host.Address,
					Port:    &a.config.HTTPWeb.Host.Port,
				},
				Skin: &a.config.HTTPWeb.Skin,
			},
			DNSProxy: &config.DNSProxy{
				Host: &config.DNSProxyServer{
					Address: &a.config.DNSProxy.Host.Address,
					Port:    &a.config.DNSProxy.Host.Port,
				},
				Upstream: &config.DNSProxyServer{
					Address: &a.config.DNSProxy.Upstream.Address,
					Port:    &a.config.DNSProxy.Upstream.Port,
				},
				Upstreams: upstreamsToFile(a.config.DNSProxy.Upstreams),
				Health: &config.DNSProxyHealth{
					Enabled:       &a.config.DNSProxy.Health.Enabled,
					Interval:      &a.config.DNSProxy.Health.Interval,
					Timeout:       &a.config.DNSProxy.Health.Timeout,
					FailCycles:    &a.config.DNSProxy.Health.FailCycles,
					RestoreCycles: &a.config.DNSProxy.Health.RestoreCycles,
					RestoreGap:    &a.config.DNSProxy.Health.RestoreGap,
				},
				DisableRemap53:  &a.config.DNSProxy.DisableRemap53,
				DisableFakePTR:  &a.config.DNSProxy.DisableFakePTR,
				DisableDropAAAA: &a.config.DNSProxy.DisableDropAAAA,
				MaxIdleConns:    &a.config.DNSProxy.MaxIdleConns,
				MaxConcurrent:   &a.config.DNSProxy.MaxConcurrent,
				Timeout:         &a.config.DNSProxy.Timeout,
			},
			Netfilter: &config.Netfilter{
				IPTables: &config.IPTables{
					ChainPrefix: &a.config.Netfilter.IPTables.ChainPrefix,
				},
				IPSet: &config.IPSet{
					TablePrefix:   &a.config.Netfilter.IPSet.TablePrefix,
					AdditionalTTL: &a.config.Netfilter.IPSet.AdditionalTTL,
				},
				DisableIPv4:         &a.config.Netfilter.DisableIPv4,
				DisableIPv6:         &a.config.Netfilter.DisableIPv6,
				StartMarkTableIndex: &a.config.Netfilter.StartMarkTableIndex,
			},
			Link:              &a.config.Link,
			ShowAllInterfaces: &a.config.ShowAllInterfaces,
			LogLevel:          &a.config.LogLevel,
		},
		Groups:        &groups,
		Subscriptions: &a.subscriptions,
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config file: %w", err)
	}
	if err := os.MkdirAll(cfgFolderLocation, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create config folder: %w", err)
	}
	// Atomic write: a power loss or a crash midway through WriteFile
	// would leave a truncated yaml without any groups.
	tmpFile := cfgFileLocation + ".tmp"
	if err := os.WriteFile(tmpFile, out, 0600); err != nil {
		return fmt.Errorf("failed to write temp config file: %w", err)
	}
	if err := os.Rename(tmpFile, cfgFileLocation); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to replace config file: %w", err)
	}
	return nil
}
