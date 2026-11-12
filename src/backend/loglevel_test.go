package magitrickle

import (
	"errors"
	"testing"

	"magitrickle/app"
	"magitrickle/constant"

	"github.com/rs/zerolog"
)

// zerologLevelByName: все имена из setupLogging разбираются, мусор - нет
func TestZerologLevelByName(t *testing.T) {
	for _, name := range []string{"trace", "debug", "info", "warn", "error", "fatal", "panic", "nolevel", "disabled"} {
		if _, ok := zerologLevelByName(name); !ok {
			t.Fatalf("уровень %q должен разбираться", name)
		}
	}
	for _, name := range []string{"", "INFO", "verbose", "warning"} {
		if _, ok := zerologLevelByName(name); ok {
			t.Fatalf("имя %q не должно разбираться", name)
		}
	}
	if l, _ := zerologLevelByName("debug"); l != zerolog.DebugLevel {
		t.Fatalf("debug -> DebugLevel, got %v", l)
	}
}

// SetLogLevel на холодном App: мусор отклоняется ДО записи (config и
// глобальный уровень не трогаются); SaveConfig на валидном пути не
// вызываем - AppStateDir вне репозитория (как в TestSetDnsUpstreamsModel)
func TestSetLogLevelColdApp(t *testing.T) {
	a := &App{config: constant.DefaultAppConfig}

	if err := a.SetLogLevel("loud"); !errors.Is(err, app.ErrLogLevelInvalid) {
		t.Fatalf("неизвестный уровень должен отвергаться c ErrLogLevelInvalid: %v", err)
	}
	if a.config.LogLevel != constant.DefaultAppConfig.LogLevel {
		t.Fatalf("после отказа уровень в модели не должен меняться: %q", a.config.LogLevel)
	}
	if a.LogLevelSnapshot() != constant.DefaultAppConfig.LogLevel {
		t.Fatalf("снапшот должен отдавать уровень модели: %q", a.LogLevelSnapshot())
	}
}
