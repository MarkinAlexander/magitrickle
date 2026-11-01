package magitrickle

// Периодическая верификация хуков (Кинетик, инцидент 01.11: группы
// «работали -> отвалились» без смены конфигурации).
//
// Корень: ndm Кинетика периодически пересобирает свой фаервол и стирает
// прыжки MT_* из builtin-цепочек, а единственный reconcile - событие
// netfilter.d - ненадёжен: события до поднятия сокета API теряются,
// iptables-restore падает на занятом xtables-lock (частично вылечено -w
// в executable-real.go), и поток.commit может обрываться на середине
// таблиц. Модель желаний при этом сохраняется, поэтому раз в тик:
//  1. ForceCommitIPTables() выкатывает дифф модель<->live (вернуть
//     стёртые прыжки/цепочки);
//  2. каждая включённая группа проверяется на наличие ВСЕХ 4 точек
//     подключения в ЖИВОМ состоянии; у группы с провалом - полный
//     пере-Enable по модели PutGroup (Disable -> Enable -> Sync),
//     это же закрывает случай "модель потеряла желания" после
//     прерванного SIGHUP/PUT-цикла.

import (
	"time"

	"magitrickle/utils/iptables"

	"github.com/rs/zerolog/log"
)

const reconcileInterval = 30 * time.Second

var groupHookPoints = []struct{ table, chain string }{
	{"filter", "FORWARD"},
	{"mangle", "PREROUTING"},
	{"mangle", "OUTPUT"},
	{"nat", "POSTROUTING"},
}

func (a *App) reconcileOnce() {
	if a.nfHelper == nil {
		return
	}

	// (1) дифф-коммит модели в live: стёртые ndm прыжки/цепочки
	// возвращаются из модели желаний
	if err := a.ForceCommitIPTables(); err != nil {
		log.Warn().Err(err).Msg("reconcile: iptables commit failed, will retry next tick")
		return
	}

	// (2) живая верификация точек подключения по каждой включённой группе
	for _, g := range a.ruleSetSnapshot() {
		if !g.Enabled() || !g.ConfiguredEnabled() {
			continue
		}
		if a.groupHooksPresent(g.RuntimeKey()) {
			continue
		}
		log.Warn().
			Str("group", g.DisplayName()).
			Str("id", g.RuntimeKey()).
			Msg("reconcile: group hooks missing, re-enabling")
		if err := g.Disable(); err != nil {
			log.Error().Err(err).Str("group", g.DisplayName()).Msg("reconcile: disable failed")
			continue
		}
		if err := g.Enable(); err != nil {
			log.Error().Err(err).Str("group", g.DisplayName()).Msg("reconcile: enable failed")
			continue
		}
		if err := g.Sync(); err != nil {
			log.Error().Err(err).Str("group", g.DisplayName()).Msg("reconcile: sync failed")
		}
	}
}

// groupHooksPresent проверяет ЖИВОЕ (не модельное) состояние: 4 прыжка
// -j/-g MT_<id> в builtin-цепочках + существование самой цепочки (тела) в
// filter/mangle/nat. Ошибка чтения live-правил не наказывает группу
// (true), чтобы не пересобирать всё при разовом сбое iptables-save.
func (a *App) groupHooksPresent(runtimeKey string) bool {
	if a.nfHelper == nil || a.nfHelper.IPTables4 == nil {
		return true
	}
	chainName := a.nfHelper.ChainPrefix + runtimeKey
	live, err := a.nfHelper.IPTables4.GetCurrentRules()
	if err != nil {
		log.Warn().Err(err).Msg("reconcile: failed to read live iptables, skipping verification")
		return true
	}
	for _, hp := range groupHookPoints {
		if !tableHasJump(live[hp.table], hp.chain, chainName) {
			return false
		}
	}
	for _, t := range []string{"filter", "mangle", "nat"} {
		// ключ существует даже для пустой цепочки (парсер ":"-строк)
		if _, exists := live[t][chainName]; !exists {
			return false
		}
	}
	return true
}

// tableHasJump ищет в живых правилах builtin-цепочки прыжок -j/-g <target>.
func tableHasJump(table map[string][]iptables.Rule, builtinChain, target string) bool {
	for _, rule := range table[builtinChain] {
		for i := 0; i+1 < len(rule); i++ {
			if (string(rule[i]) == "-j" || string(rule[i]) == "-g") && string(rule[i+1]) == target {
				return true
			}
		}
	}
	return false
}
