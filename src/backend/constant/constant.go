package constant

import (
	"time"

	"magitrickle/models"
)

var DefaultAppConfig = models.AppConfig{
	DNSProxy: models.AppConfigDNSProxy{
		Host:     models.AppConfigDNSProxyServer{Address: "[::]", Port: 3553},
		Upstream: models.AppConfigDNSProxyServer{Address: "127.0.0.1", Port: 53},
		Health: models.AppConfigDNSProxyHealth{
			Enabled:       true,
			Interval:      10 * time.Second,
			Timeout:       2 * time.Second,
			FailCycles:    3,
			RestoreCycles: 2,
			RestoreGap:    5 * time.Minute,
		},
		DisableRemap53:  false,
		DisableFakePTR:  false,
		DisableDropAAAA: false,
		MaxIdleConns:    10,
		MaxConcurrent:   100,
		Timeout:         5000 * time.Millisecond,
	},
	HTTPWeb: models.AppConfigHTTPWeb{
		Enabled: true,
		Auth: models.AppConfigAuth{
			Enabled: false,
		},
		Host: models.AppConfigHTTPWebServer{
			Address: "[::]",
			Port:    8080,
		},
		Skin: "default",
	},
	Netfilter: models.AppConfigNetfilter{
		IPTables: models.AppConfigIPTables{
			ChainPrefix: "MT_",
		},
		IPSet: models.AppConfigIPSet{
			TablePrefix:   "mt_",
			AdditionalTTL: 1 * time.Hour,
		},
		DisableIPv4:         false,
		DisableIPv6:         false,
		StartMarkTableIndex: 0x4D616769, // Magi
	},
	Link:              []string{"br0"},
	ShowAllInterfaces: false,
	LogLevel:          "info",
}

var (
	Version = "unattached"
)
