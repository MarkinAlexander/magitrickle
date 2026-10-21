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
// приоритет. Поле Upstreams опционально с rev14: отсутствует (nil) =
// список не трогать (запись только health). Старым клиентам без поля
// health всё совместимо: неизвестный JSON игнорируется.
type DnsUpstreamsPutReq struct {
	Upstreams []string         `json:"upstreams"`
	Health    *DnsHealthPutReq `json:"health,omitempty"`
}

// DnsHealthPutReq - правка политики зондов апстримов (rev14: управление
// нагрузкой проб из панели): nil-поля = «не трогать», длительности в
// секундах. Каждое поле влияет и на скорость реакции, и на всплески
// нагрузки - интервал/таймаут проверяют серверы, циклы/пауза - гистерезис
// переключений.
type DnsHealthPutReq struct {
	Enabled       *bool `json:"enabled" example:"true"`
	IntervalSec   *uint `json:"intervalSec" example:"10"`
	TimeoutSec    *uint `json:"timeoutSec" example:"2"`
	FailCycles    *uint `json:"failCycles" example:"3"`
	RestoreCycles *uint `json:"restoreCycles" example:"2"`
	RestoreGapSec *uint `json:"restoreGapSec" example:"300"`
}

// DnsZonesRes - состояние зонного DNS (API rev13): таблица зон со стейтом
// апстримов каждой; читается контроллером mawg для карточки «Зонные DNS».
type DnsZonesRes struct {
	// Available=false - dns-proxy ещё не построен (демон до Start);
	// Zones при этом пуст.
	Available bool         `json:"available"`
	Zones     []DnsZoneRes `json:"zones"`
}

// DnsZoneRes - одна зона: имя без хвостовой точки, fallback-политика и
// стейт её апстримов (порядок = приоритет, active - первый живой).
type DnsZoneRes struct {
	Zone      string             `json:"zone" example:"corp.example.com"`
	Fallback  bool               `json:"fallback"`
	Upstreams []DnsUpstreamState `json:"upstreams"`
}

// DnsZonePut - запись редактора зон (rev13): имя зоны (покрывает себя и
// все поддомены), её упорядоченные апстримы (формат общего каскада) и
// Fallback - разрешить деградацию в общий каскад при полном отвале зоны
// (по умолчанию false = fail-closed, SERVFAIL).
type DnsZonePut struct {
	Zone      string   `json:"zone"`
	Upstreams []string `json:"upstreams"`
	Fallback  bool     `json:"fallback"`
}

// DnsZonesPutReq - замена всей таблицы зон (PUT); пустой список = очистка.
type DnsZonesPutReq struct {
	Zones []DnsZonePut `json:"zones"`
}
