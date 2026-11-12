package types

type NetfilterDHookReq struct {
	Type  string `json:"type" example:"iptables"`
	Table string `json:"table" example:"nat"`
}

// LogLevelRes - текущий уровень лога демона.
type LogLevelRes struct {
	Level string `json:"level" example:"info"`
}

// LogLevelPutReq - смена уровня лога (trace/debug/info/warn/error/fatal/panic/nolevel/disabled).
type LogLevelPutReq struct {
	Level string `json:"level" example:"info"`
}
