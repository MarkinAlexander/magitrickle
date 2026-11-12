package magitrickle

import (
	"fmt"

	"magitrickle/app"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// zerologLevelByName - имя уровня из конфига/API -> zerolog.Level;
// ok=false на неизвестном имени.
func zerologLevelByName(level string) (zerolog.Level, bool) {
	switch level {
	case "trace":
		return zerolog.TraceLevel, true
	case "debug":
		return zerolog.DebugLevel, true
	case "info":
		return zerolog.InfoLevel, true
	case "warn":
		return zerolog.WarnLevel, true
	case "error":
		return zerolog.ErrorLevel, true
	case "fatal":
		return zerolog.FatalLevel, true
	case "panic":
		return zerolog.PanicLevel, true
	case "nolevel":
		return zerolog.NoLevel, true
	case "disabled":
		return zerolog.Disabled, true
	}
	return zerolog.InfoLevel, false
}

// SetLogLevel - смена уровня лога на лету (API rev22): глобальный уровень
// zerolog + запись в конфиг (переживает рестарт). Неизвестное имя
// отклоняем, а не тихо подменяем дефолтом: пользователь должен видеть,
// что уровень не применился.
func (a *App) SetLogLevel(level string) error {
	l, ok := zerologLevelByName(level)
	if !ok {
		return fmt.Errorf("%w: %q", app.ErrLogLevelInvalid, level)
	}
	a.stateMu.Lock()
	a.config.LogLevel = level
	a.stateMu.Unlock()
	if err := a.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	zerolog.SetGlobalLevel(l)
	log.Info().Str("level", level).Msg("log level changed via api")
	return nil
}

// LogLevelSnapshot - текущий уровень лога (API rev22).
func (a *App) LogLevelSnapshot() string {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.config.LogLevel
}
