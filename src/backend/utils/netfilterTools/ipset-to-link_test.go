//go:build testing

package netfilterTools

import (
	"reflect"
	"testing"

	"magitrickle/utils/iptables"
)

// helper: новый fake с зарегистрированными builtin-цепочками (как при
// старте Helper) - insertIPTablesRules прыгает во все четыре
func newTestIPTables(proto iptables.Protocol) (*iptables.FakeIPTables, *iptables.IPTables) {
	fake := iptables.NewFakeIPTables(proto)
	ipt := iptables.NewIPTables(fake)
	for _, tc := range [][2]string{
		{"filter", "FORWARD"},
		{"mangle", "PREROUTING"},
		{"mangle", "OUTPUT"},
		{"nat", "POSTROUTING"},
	} {
		if err := ipt.RegisterChainPatch(tc[0], tc[1]); err != nil {
			panic(err)
		}
	}
	return fake, ipt
}

// guard-правило ограничения источников: первое правило mangle-цепочки
// группы, отрицательный матч по постоянному src-ипсету mt_<id>_src_4/_6
func TestSourceGuardRule(t *testing.T) {
	dst := &IPSet{ipsetName: "mt_0a1b2c3d"}
	src := &IPSet{ipsetName: "mt_0a1b2c3d_src"}
	nh := &Helper{ChainPrefix: "MT_"}

	link := nh.IPSetToLink("0a1b2c3d", "nwg0", dst, src, false)

	fake, ipt := newTestIPTables(iptables.ProtocolIPv4)
	if err := link.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules: %v", err)
	}

	rules := fake.GetRules("mangle", "MT_0a1b2c3d")
	if len(rules) < 4 {
		t.Fatalf("mangle chain too short: %v", rules)
	}
	want := []string{"-m", "set", "!", "--match-set", "mt_0a1b2c3d_src_4", "src", "-j", "RETURN"}
	if !reflect.DeepEqual(rules[0], want) {
		t.Fatalf("guard rule not first in mangle chain:\n got %v\nwant %v", rules[0], want)
	}
	// MARK идёт после guard
	if !reflect.DeepEqual(rules[1], []string{"-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"}) {
		t.Fatalf("ctdir RETURN not second: %v", rules[1])
	}

	// v6: суффикс _6 в имени src-сета
	link6 := nh.IPSetToLink("0a1b2c3d", "nwg0", dst, src, false)
	fake6, ipt6 := newTestIPTables(iptables.ProtocolIPv6)
	if err := link6.insertIPTablesRules(ipt6); err != nil {
		t.Fatalf("insertIPTablesRules v6: %v", err)
	}
	rules6 := fake6.GetRules("mangle", "MT_0a1b2c3d")
	want6 := []string{"-m", "set", "!", "--match-set", "mt_0a1b2c3d_src_6", "src", "-j", "RETURN"}
	if !reflect.DeepEqual(rules6[0], want6) {
		t.Fatalf("guard rule v6 not first:\n got %v\nwant %v", rules6[0], want6)
	}
}

// без списка источников цепочка остаётся ровно прежней - guard не ставится
func TestNoSourceGuardWithoutSrcSet(t *testing.T) {
	dst := &IPSet{ipsetName: "mt_0a1b2c3d"}
	nh := &Helper{ChainPrefix: "MT_"}

	link := nh.IPSetToLink("0a1b2c3d", "nwg0", dst, nil, false)
	fake, ipt := newTestIPTables(iptables.ProtocolIPv4)
	if err := link.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules: %v", err)
	}

	rules := fake.GetRules("mangle", "MT_0a1b2c3d")
	if len(rules) != 3 {
		t.Fatalf("mangle chain length %d, want 3: %v", len(rules), rules)
	}
	if !reflect.DeepEqual(rules[0], []string{"-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN"}) {
		t.Fatalf("first rule changed: %v", rules[0])
	}
}

// OUTPUT-jump роутерного трафика (64-док §5): джамп в общую mangle-цепочку
// группы ставится и снимается вместе с группой - маркировка DNS-запросов
// самого роутера больше не зависит от ручных правил
func TestMangleOutputJump(t *testing.T) {
	dst := &IPSet{ipsetName: "mt_0a1b2c3d"}
	nh := &Helper{ChainPrefix: "MT_"}

	link := nh.IPSetToLink("0a1b2c3d", "nwg0", dst, nil, false)
	fake, ipt := newTestIPTables(iptables.ProtocolIPv4)
	if err := link.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules: %v", err)
	}
	want := []string{"-j", "MT_0a1b2c3d"}
	var found bool
	for _, r := range fake.GetRules("mangle", "OUTPUT") {
		if reflect.DeepEqual(r, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("OUTPUT jump missing: %v", fake.GetRules("mangle", "OUTPUT"))
	}

	if err := link.deleteIPTablesRules(ipt); err != nil {
		t.Fatalf("deleteIPTablesRules: %v", err)
	}
	for _, r := range fake.GetRules("mangle", "OUTPUT") {
		if reflect.DeepEqual(r, want) {
			t.Fatalf("OUTPUT jump survived delete")
		}
	}
}

// localOnly-группа: OUTPUT-прыжка нет вовсе (роутер вне группы, инцидент
// затора 21.11), остальные точки подключения и тело цепочки - как обычно
func TestLocalOnlyNoOutputJump(t *testing.T) {
	dst := &IPSet{ipsetName: "mt_0a1b2c3d"}
	nh := &Helper{ChainPrefix: "MT_"}

	link := nh.IPSetToLink("0a1b2c3d", "nwg0", dst, nil, true)
	fake, ipt := newTestIPTables(iptables.ProtocolIPv4)
	if err := link.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules: %v", err)
	}

	want := []string{"-j", "MT_0a1b2c3d"}
	for _, r := range fake.GetRules("mangle", "OUTPUT") {
		if reflect.DeepEqual(r, want) {
			t.Fatalf("localOnly group got OUTPUT jump: %v", fake.GetRules("mangle", "OUTPUT"))
		}
	}
	var found bool
	for _, r := range fake.GetRules("mangle", "PREROUTING") {
		if reflect.DeepEqual(r, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("PREROUTING jump missing for localOnly group")
	}

	// снятие группы чисто: несуществующий OUTPUT-джамп не ломает delete
	if err := link.deleteIPTablesRules(ipt); err != nil {
		t.Fatalf("deleteIPTablesRules: %v", err)
	}
}

// флип флага на пересборке: localOnly=false возвращает OUTPUT-прыжок
func TestLocalOnlyFlipRestoresOutputJump(t *testing.T) {
	dst := &IPSet{ipsetName: "mt_0a1b2c3d"}
	nh := &Helper{ChainPrefix: "MT_"}

	fake, ipt := newTestIPTables(iptables.ProtocolIPv4)
	link := nh.IPSetToLink("0a1b2c3d", "nwg0", dst, nil, true)
	if err := link.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insert localOnly: %v", err)
	}
	if err := link.deleteIPTablesRules(ipt); err != nil {
		t.Fatalf("delete localOnly: %v", err)
	}

	link2 := nh.IPSetToLink("0a1b2c3d", "nwg0", dst, nil, false)
	if err := link2.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insert after flip: %v", err)
	}
	want := []string{"-j", "MT_0a1b2c3d"}
	var found bool
	for _, r := range fake.GetRules("mangle", "OUTPUT") {
		if reflect.DeepEqual(r, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("OUTPUT jump missing after flip: %v", fake.GetRules("mangle", "OUTPUT"))
	}
}
