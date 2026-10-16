package types

import "time"

// DnsUpstreamsRes - состояние каскада апстримов dns-proxy (API rev8):
// читается контроллером mawg для карточки «Каскад MT».
type DnsUpstreamsRes struct {
	// Available=false - dns-proxy ещё не построен (демон до Start);
	// Upstreams при этом пуст.
	Available bool               `json:"available"`
	Health    DnsHealthRes       `json:"health"`
	Upstreams []DnsUpstreamState `json:"upstreams"`
}

// DnsHealthRes - политика зондов-канареек (длительности строками: "10s").
type DnsHealthRes struct {
	Enabled       bool   `json:"enabled"`
	Interval      string `json:"interval"`
	Timeout       string `json:"timeout"`
	FailCycles    uint   `json:"failCycles"`
	RestoreCycles uint   `json:"restoreCycles"`
	RestoreGap    string `json:"restoreGap"`
}

// DnsUpstreamState - здоровье одного апстрима: порядок в списке =
// приоритет, active - первый живой (в него идут клиентские запросы).
type DnsUpstreamState struct {
	Address  string    `json:"address" example:"8.8.8.8:53"`
	Alive    bool      `json:"alive"`
	Active   bool      `json:"active"`
	Fails    uint      `json:"fails"`
	Oks      uint      `json:"oks"`
	LastSwap time.Time `json:"lastSwap"`
	Reason   string    `json:"reason,omitempty" example:"dial: i/o timeout"`
}

// DnsUpstreamsPutReq - замена списка апстримов (редактор каскада mawg):
// адреса "8.8.8.8" или "8.8.8.8:5353" (порт по умолчанию 53), порядок =
// приоритет; список непустой обязателен.
type DnsUpstreamsPutReq struct {
	Upstreams []string `json:"upstreams"`
}
