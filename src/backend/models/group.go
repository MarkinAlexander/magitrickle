package models

import (
	"magitrickle/utils/intID"
)

type Group struct {
	ID        intID.ID `yaml:"id"`
	Name      string   `yaml:"name"`
	Color     string   `yaml:"color"`
	Interface string   `yaml:"interface"`
	Enable    bool     `yaml:"enable"`
	Sources   []string `yaml:"sources,omitempty"`
	// LocalOnly - группа не обрабатывает трафик самого роутера: mangle
	// OUTPUT-прыжок не ставится, LAN идёт по PREROUTING как раньше
	// (reconcile не считает отсутствие прыжка пропажей). Контроллер
	// ставит для пуловых групп «вся локалка»: пробы/DNS/проверки роутера
	// идут напрямую (инцидент затора 21.11: googlevideo-проба уходила в
	// туннель группы). Пусто = прежнее поведение (прыжок есть).
	LocalOnly bool    `yaml:"localOnly,omitempty"`
	Rules     []*Rule `yaml:"rules"`
}
