package config

import "time"

type App struct {
	HTTPWeb           *HTTPWeb   `yaml:"httpWeb"`
	DNSProxy          *DNSProxy  `yaml:"dnsProxy"`
	Netfilter         *Netfilter `yaml:"netfilter"`
	Link              *[]string  `yaml:"link"`
	ShowAllInterfaces *bool      `yaml:"showAllInterfaces"`
	LogLevel          *string    `yaml:"logLevel"`
}

type HTTPWeb struct {
	Enabled *bool          `yaml:"enabled"`
	Auth    *Auth          `yaml:"auth"`
	Host    *HTTPWebServer `yaml:"host"`
	Skin    *string        `yaml:"skin"`
}

type Auth struct {
	Enabled *bool `yaml:"enabled"`
}

type HTTPWebServer struct {
	Address *string `yaml:"address"`
	Port    *uint16 `yaml:"port"`
}

type DNSProxy struct {
	Host     *DNSProxyServer   `yaml:"host"`
	Upstream *DNSProxyServer   `yaml:"upstream"`
	// Upstreams - упорядоченный список апстримов (приоритет = порядок,
	// 43-док §5); непустой список вытесняет одиночный Upstream.
	Upstreams *[]DNSProxyServer `yaml:"upstreams"`
	// Zones - зонный DNS (rev13): доменные зоны с собственными
	// упорядоченными апстримами; запрос имени из зоны обслуживает
	// список зоны, общий каскад не участвует (fail-closed по умолчанию).
	Zones *[]DNSProxyZone `yaml:"zones"`
	// Health - зонды-канарейки апстримов с гистерезисом K/M (46-док §3).
	Health          *DNSProxyHealth `yaml:"health"`
	DisableRemap53  *bool           `yaml:"disableRemap53"`
	DisableFakePTR  *bool           `yaml:"disableFakePTR"`
	DisableDropAAAA *bool           `yaml:"disableDropAAAA"`
	MaxIdleConns    *uint           `yaml:"maxIdleConns"`
	MaxConcurrent   *uint           `yaml:"maxConcurrent"`
	Timeout         *time.Duration  `yaml:"timeout"`
}

// DNSProxyZone - запись зонного DNS (rev13): имя зоны (без хвостовой
// точки; зона покрывает себя и все поддомены), упорядоченный список её
// апстримов (тот же формат, что у общего каскада) и Fallback - разрешить
// ли деградацию в общий каскад, когда не ответил ни один сервер зоны
// (по умолчанию false = fail-closed, SERVFAIL).
type DNSProxyZone struct {
	Zone      *string           `yaml:"zone"`
	Upstreams *[]DNSProxyServer `yaml:"upstreams"`
	Fallback  *bool             `yaml:"fallback"`
}

type DNSProxyHealth struct {
	Enabled       *bool          `yaml:"enabled"`
	Interval      *time.Duration `yaml:"interval"`
	Timeout       *time.Duration `yaml:"timeout"`
	FailCycles    *uint          `yaml:"failCycles"`
	RestoreCycles *uint          `yaml:"restoreCycles"`
	RestoreGap    *time.Duration `yaml:"restoreGap"`
}

type DNSProxyServer struct {
	Address *string `yaml:"address"`
	Port    *uint16 `yaml:"port"`
}

type Netfilter struct {
	IPTables            *IPTables `yaml:"iptables"`
	IPSet               *IPSet    `yaml:"ipset"`
	DisableIPv4         *bool     `yaml:"disableIPv4"`
	DisableIPv6         *bool     `yaml:"disableIPv6"`
	StartMarkTableIndex *uint32   `yaml:"startMarkTableIndex"`
}

type IPTables struct {
	ChainPrefix *string `yaml:"chainPrefix"`
}

type IPSet struct {
	TablePrefix   *string        `yaml:"tablePrefix"`
	AdditionalTTL *time.Duration `yaml:"additionalTTL"`
}
