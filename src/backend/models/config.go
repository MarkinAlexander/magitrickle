package models

import "time"

type AppConfig struct {
	HTTPWeb           AppConfigHTTPWeb
	DNSProxy          AppConfigDNSProxy
	Netfilter         AppConfigNetfilter
	Link              []string
	ShowAllInterfaces bool
	LogLevel          string
}

type AppConfigHTTPWeb struct {
	Enabled bool
	Auth    AppConfigAuth
	Host    AppConfigHTTPWebServer
	Skin    string
}

type AppConfigAuth struct {
	Enabled bool
}

type AppConfigHTTPWebServer struct {
	Address string
	Port    uint16
}

type AppConfigDNSProxy struct {
	Host            AppConfigDNSProxyServer
	Upstream        AppConfigDNSProxyServer
	Upstreams       []AppConfigDNSProxyServer
	Health          AppConfigDNSProxyHealth
	DisableRemap53  bool
	DisableFakePTR  bool
	DisableDropAAAA bool
	MaxIdleConns    uint
	MaxConcurrent   uint
	Timeout         time.Duration
}

type AppConfigDNSProxyServer struct {
	Address string
	Port    uint16
}

// AppConfigDNSProxyHealth - политика зондов апстримов (46-док §3):
// вниз - K неудач подряд, вверх - M успехов подряд и не чаще раза в
// RestoreGap; зонды - канарейка-контент-чек (63-док, эмпирика Фазы E:
// живость без проверки контента бесполезна на отравленной сети).
type AppConfigDNSProxyHealth struct {
	Enabled       bool
	Interval      time.Duration
	Timeout       time.Duration
	FailCycles    uint
	RestoreCycles uint
	RestoreGap    time.Duration
}

// UpstreamList - эффективный список апстримов: непустой Upstreams
// вытесняет одиночный Upstream (обратная совместимость, 43-док §5).
func (c AppConfigDNSProxy) UpstreamList() []AppConfigDNSProxyServer {
	if len(c.Upstreams) > 0 {
		return c.Upstreams
	}
	return []AppConfigDNSProxyServer{c.Upstream}
}

type AppConfigNetfilter struct {
	IPTables            AppConfigIPTables
	IPSet               AppConfigIPSet
	DisableIPv4         bool
	DisableIPv6         bool
	StartMarkTableIndex uint32
}

type AppConfigIPTables struct {
	ChainPrefix string
}

type AppConfigIPSet struct {
	TablePrefix   string
	AdditionalTTL time.Duration
}
