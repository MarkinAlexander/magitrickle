//go:build testing

package iptables

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestChainPatch проверяет, что правила добавляются к существующим
func TestChainPatch(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	// Начальное состояние: в chain уже есть правила
	fake.SetInitialRules("filter", "FORWARD", [][]string{
		{"-i", "eth0", "-j", "ACCEPT"},
		{"-i", "eth1", "-j", "DROP"},
	})

	ipt := NewIPTables(fake)

	// Регистрируем chain как overlay
	err := ipt.RegisterChainPatch("filter", "FORWARD")
	if err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}

	// Добавляем новое правило
	err = ipt.Append("filter", "FORWARD", "-i", "eth2", "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Коммитим
	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Проверяем результат: старые правила должны остаться, новое добавиться в конец
	rules := fake.GetRules("filter", "FORWARD")
	expected := [][]string{
		{"-i", "eth0", "-j", "ACCEPT"},
		{"-i", "eth1", "-j", "DROP"},
		{"-i", "eth2", "-j", "ACCEPT"},
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("Patch failed.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestChainPatchDelete проверяет удаление правил в overlay режиме
func TestChainPatchDelete(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	fake.SetInitialRules("filter", "INPUT", [][]string{
		{"-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
		{"-p", "tcp", "--dport", "80", "-j", "ACCEPT"},
		{"-p", "tcp", "--dport", "443", "-j", "ACCEPT"},
	})

	ipt := NewIPTables(fake)

	err := ipt.RegisterChainPatch("filter", "INPUT")
	if err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}

	// Удаляем правило для порта 80
	err = ipt.Delete("filter", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	rules := fake.GetRules("filter", "INPUT")
	expected := [][]string{
		{"-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
		{"-p", "tcp", "--dport", "443", "-j", "ACCEPT"},
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("Patch delete failed.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestChainPatchInsert проверяет вставку правил в начало
func TestChainPatchInsert(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	fake.SetInitialRules("filter", "OUTPUT", [][]string{
		{"-d", "10.0.0.0/8", "-j", "ACCEPT"},
	})

	ipt := NewIPTables(fake)

	err := ipt.RegisterChainPatch("filter", "OUTPUT")
	if err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}

	// Вставляем правило в начало (позиция 1)
	err = ipt.Insert("filter", "OUTPUT", 1, "-d", "192.168.0.0/16", "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	rules := fake.GetRules("filter", "OUTPUT")
	expected := [][]string{
		{"-d", "192.168.0.0/16", "-j", "ACCEPT"},
		{"-d", "10.0.0.0/8", "-j", "ACCEPT"},
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("Patch insert failed.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestChainPatchNoDuplicates проверяет, что дубликаты не добавляются
func TestChainPatchNoDuplicates(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	fake.SetInitialRules("filter", "FORWARD", [][]string{
		{"-i", "eth0", "-j", "ACCEPT"},
	})

	ipt := NewIPTables(fake)

	err := ipt.RegisterChainPatch("filter", "FORWARD")
	if err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}

	// Пытаемся добавить уже существующее правило
	err = ipt.Append("filter", "FORWARD", "-i", "eth0", "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	rules := fake.GetRules("filter", "FORWARD")
	expected := [][]string{
		{"-i", "eth0", "-j", "ACCEPT"},
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("Patch should not duplicate rules.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestChainOverride проверяет полную замену chain
func TestChainOverride(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	// Начальное состояние: chain с правилами
	fake.SetInitialRules("nat", "PREROUTING", [][]string{
		{"-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8080"},
		{"-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8443"},
	})

	ipt := NewIPTables(fake)

	// Регистрируем как override - полная замена
	err := ipt.RegisterChainOverride("nat", "PREROUTING")
	if err != nil {
		t.Fatalf("RegisterChainOverride failed: %v", err)
	}

	// Добавляем новые правила (они заменят старые)
	err = ipt.Append("nat", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "5353")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Проверяем: старые правила должны исчезнуть, остаться только новое
	rules := fake.GetRules("nat", "PREROUTING")
	expected := [][]string{
		{"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "5353"},
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("Override failed.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestChainOverrideMultipleRules проверяет замену несколькими правилами
func TestChainOverrideMultipleRules(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	fake.SetInitialRules("mangle", "PREROUTING", [][]string{
		{"-j", "OLD_CHAIN"},
	})

	ipt := NewIPTables(fake)

	err := ipt.RegisterChainOverride("mangle", "PREROUTING")
	if err != nil {
		t.Fatalf("RegisterChainOverride failed: %v", err)
	}

	// Добавляем несколько правил
	err = ipt.Append("mangle", "PREROUTING", "-j", "MARK", "--set-mark", "1")
	if err != nil {
		t.Fatalf("Append 1 failed: %v", err)
	}

	err = ipt.Append("mangle", "PREROUTING", "-j", "MARK", "--set-mark", "2")
	if err != nil {
		t.Fatalf("Append 2 failed: %v", err)
	}

	err = ipt.Append("mangle", "PREROUTING", "-j", "CONNMARK", "--save-mark")
	if err != nil {
		t.Fatalf("Append 3 failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	rules := fake.GetRules("mangle", "PREROUTING")
	expected := [][]string{
		{"-j", "MARK", "--set-mark", "1"},
		{"-j", "MARK", "--set-mark", "2"},
		{"-j", "CONNMARK", "--save-mark"},
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("Override with multiple rules failed.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestChainOverrideNoChangeIfSame проверяет, что если правила не изменились, ничего не происходит
func TestChainOverrideNoChangeIfSame(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	fake.SetInitialRules("filter", "TEST", [][]string{
		{"-j", "ACCEPT"},
	})

	ipt := NewIPTables(fake)

	err := ipt.RegisterChainOverride("filter", "TEST")
	if err != nil {
		t.Fatalf("RegisterChainOverride failed: %v", err)
	}

	// Добавляем то же самое правило
	err = ipt.Append("filter", "TEST", "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	rules := fake.GetRules("filter", "TEST")
	expected := [][]string{
		{"-j", "ACCEPT"},
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("Override same rules failed.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestChainDelete проверяет удаление chain
func TestChainDelete(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	// Создаём chain с правилами
	fake.SetInitialRules("filter", "MY_CHAIN", [][]string{
		{"-j", "ACCEPT"},
		{"-j", "DROP"},
	})

	ipt := NewIPTables(fake)

	// Регистрируем для удаления
	err := ipt.RegisterChainDelete("filter", "MY_CHAIN")
	if err != nil {
		t.Fatalf("RegisterChainDelete failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Проверяем, что chain удалён
	if fake.ChainExists("filter", "MY_CHAIN") {
		t.Error("Chain should be deleted but still exists")
	}
}

// TestChainDeleteEmpty проверяет удаление пустого chain
func TestChainDeleteEmpty(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	// Создаём пустой chain
	fake.SetInitialRules("filter", "EMPTY_CHAIN", [][]string{})

	ipt := NewIPTables(fake)

	err := ipt.RegisterChainDelete("filter", "EMPTY_CHAIN")
	if err != nil {
		t.Fatalf("RegisterChainDelete failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if fake.ChainExists("filter", "EMPTY_CHAIN") {
		t.Error("Empty chain should be deleted but still exists")
	}
}

// TestChainDeleteNonExistent проверяет, что удаление несуществующего chain не вызывает ошибок
func TestChainDeleteNonExistent(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	// НЕ создаём chain - он не существует

	ipt := NewIPTables(fake)

	err := ipt.RegisterChainDelete("filter", "NON_EXISTENT")
	if err != nil {
		t.Fatalf("RegisterChainDelete failed: %v", err)
	}

	// Commit не должен падать
	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Chain по-прежнему не существует
	if fake.ChainExists("filter", "NON_EXISTENT") {
		t.Error("Non-existent chain should not be created")
	}
}

// TestChainDeleteIgnoresAppend проверяет, что Append/Insert/Delete игнорируются для удаляемого chain
func TestChainDeleteIgnoresAppend(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	fake.SetInitialRules("filter", "TO_DELETE", [][]string{
		{"-j", "ACCEPT"},
	})

	ipt := NewIPTables(fake)

	err := ipt.RegisterChainDelete("filter", "TO_DELETE")
	if err != nil {
		t.Fatalf("RegisterChainDelete failed: %v", err)
	}

	// Эти операции должны быть проигнорированы
	_ = ipt.Append("filter", "TO_DELETE", "-j", "DROP")
	_ = ipt.Insert("filter", "TO_DELETE", 1, "-j", "LOG")
	_ = ipt.Delete("filter", "TO_DELETE", "-j", "ACCEPT")

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if fake.ChainExists("filter", "TO_DELETE") {
		t.Error("Chain should be deleted")
	}
}

// TestMixedChainTypes проверяет работу разных типов chain в одной таблице
func TestMixedChainTypes(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	// Начальное состояние
	fake.SetInitialRules("filter", "INPUT", [][]string{
		{"-j", "ACCEPT"},
	})
	fake.SetInitialRules("filter", "FORWARD", [][]string{
		{"-j", "OLD_RULE"},
	})
	fake.SetInitialRules("filter", "TO_DELETE", [][]string{
		{"-j", "SOMETHING"},
	})

	ipt := NewIPTables(fake)

	// INPUT - overlay (добавляем к существующим)
	_ = ipt.RegisterChainPatch("filter", "INPUT")
	_ = ipt.Append("filter", "INPUT", "-j", "DROP")

	// FORWARD - override (заменяем полностью)
	_ = ipt.RegisterChainOverride("filter", "FORWARD")
	_ = ipt.Append("filter", "FORWARD", "-j", "NEW_RULE")

	// TO_DELETE - удаляем
	_ = ipt.RegisterChainDelete("filter", "TO_DELETE")

	err := ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Проверяем INPUT (overlay)
	inputRules := fake.GetRules("filter", "INPUT")
	expectedInput := [][]string{
		{"-j", "ACCEPT"},
		{"-j", "DROP"},
	}
	if !reflect.DeepEqual(inputRules, expectedInput) {
		t.Errorf("INPUT overlay failed.\nExpected: %v\nGot: %v", expectedInput, inputRules)
	}

	// Проверяем FORWARD (override)
	forwardRules := fake.GetRules("filter", "FORWARD")
	expectedForward := [][]string{
		{"-j", "NEW_RULE"},
	}
	if !reflect.DeepEqual(forwardRules, expectedForward) {
		t.Errorf("FORWARD override failed.\nExpected: %v\nGot: %v", expectedForward, forwardRules)
	}

	// Проверяем TO_DELETE (должен быть удалён)
	if fake.ChainExists("filter", "TO_DELETE") {
		t.Error("TO_DELETE chain should not exist")
	}
}

// TestMultipleCommits проверяет несколько последовательных коммитов
func TestMultipleCommits(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	ipt := NewIPTables(fake)

	// Первый коммит: создаём chain
	_ = ipt.RegisterChainOverride("filter", "MY_CHAIN")
	_ = ipt.Append("filter", "MY_CHAIN", "-j", "ACCEPT")

	err := ipt.Commit()
	if err != nil {
		t.Fatalf("First commit failed: %v", err)
	}

	rules := fake.GetRules("filter", "MY_CHAIN")
	if len(rules) != 1 || rules[0][1] != "ACCEPT" {
		t.Errorf("After first commit: %v", rules)
	}

	// Второй коммит: добавляем ещё правило
	_ = ipt.Append("filter", "MY_CHAIN", "-j", "DROP")

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Second commit failed: %v", err)
	}

	rules = fake.GetRules("filter", "MY_CHAIN")
	expected := [][]string{
		{"-j", "ACCEPT"},
		{"-j", "DROP"},
	}
	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("After second commit.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestIPv6 проверяет работу с IPv6
func TestIPv6(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv6)

	ipt := NewIPTables(fake)

	if ipt.Proto() != ProtocolIPv6 {
		t.Error("Protocol should be IPv6")
	}

	_ = ipt.RegisterChainOverride("filter", "INPUT")
	_ = ipt.Append("filter", "INPUT", "-s", "::1", "-j", "ACCEPT")

	err := ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	rules := fake.GetRules("filter", "INPUT")
	expected := [][]string{
		{"-s", "::1", "-j", "ACCEPT"},
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("IPv6 rules failed.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestErrorOnUninitializedChain проверяет ошибку при работе с незарегистрированным chain
func TestErrorOnUninitializedChain(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)
	ipt := NewIPTables(fake)

	err := ipt.Append("filter", "NONEXISTENT", "-j", "ACCEPT")
	if err != ErrChainNotInitialized {
		t.Errorf("Expected ErrChainNotInitialized, got: %v", err)
	}

	err = ipt.Insert("filter", "NONEXISTENT", 1, "-j", "ACCEPT")
	if err != ErrChainNotInitialized {
		t.Errorf("Expected ErrChainNotInitialized, got: %v", err)
	}

	err = ipt.Delete("filter", "NONEXISTENT", "-j", "ACCEPT")
	if err != ErrChainNotInitialized {
		t.Errorf("Expected ErrChainNotInitialized, got: %v", err)
	}
}

// TestPatchRemovesDuplicates проверяет удаление дубликатов в overlay
func TestPatchRemovesDuplicates(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)

	// Начальное состояние с дубликатами
	fake.SetInitialRules("filter", "FORWARD", [][]string{
		{"-j", "ACCEPT"},
		{"-j", "ACCEPT"}, // дубликат
		{"-j", "DROP"},
	})

	ipt := NewIPTables(fake)

	err := ipt.RegisterChainPatch("filter", "FORWARD")
	if err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}

	// Append того же правила должен удалить дубликаты, но не добавить новое
	err = ipt.Append("filter", "FORWARD", "-j", "ACCEPT")
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	rules := fake.GetRules("filter", "FORWARD")
	// Должен остаться только один -j ACCEPT и один -j DROP
	expected := [][]string{
		{"-j", "ACCEPT"},
		{"-j", "DROP"},
	}

	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("Patch duplicate removal failed.\nExpected: %v\nGot: %v", expected, rules)
	}
}

// TestRestoreErrorContext: ошибка iptables-restore должна называть
// конкретную строку потока, а не безликое "line N failed"
func TestRestoreErrorContext(t *testing.T) {
	stream := "*mangle\n:MT_a - -\n-A MT_a -j MARK\n-A MT_b -j FOO\nCOMMIT\n"
	stderr := "iptables-restore: line 4 failed\n"
	got := restoreErrorContext(stderr, []byte(stream))
	want := ` (stream line 4: "-A MT_b -j FOO")`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := restoreErrorContext("no line info", []byte(stream)); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
	if got := restoreErrorContext("line 99 failed", []byte(stream)); got != "" {
		t.Fatalf("line beyond stream: want empty, got %q", got)
	}
}

// recordingFake пишет вызовы Restore - для проверки потабличного фолбэка
type recordingFake struct {
	*FakeIPTables
	calls [][]byte
	// failMultiTable: отказ на общем потоке из 2+ таблиц, успех потаблично
	failMultiTable bool
	// failAll: отказ всегда (тест честной ошибки)
	failAll bool
}

func (r *recordingFake) Restore(data []byte) error {
	r.calls = append(r.calls, append([]byte(nil), data...))
	if r.failAll {
		return errRestoreBoom
	}
	if r.failMultiTable && countCommits(data) > 1 {
		return errRestoreBoom
	}
	return r.FakeIPTables.Restore(data)
}

func countCommits(data []byte) int {
	return bytes.Count(data, []byte("COMMIT"))
}

var errRestoreBoom = errors.New("restore boom: line 70 failed (COMMIT)")

// Потабличный фолбэк (инцидент геоблока 03.11): отказ общего потока двух
// таблиц раньше валил всё - теперь таблицы досылаются по одной, хвост
// failed-стрима уходит в ошибку с именем таблицы.
func TestCommitPerTableFallback(t *testing.T) {
	rec := &recordingFake{FakeIPTables: NewFakeIPTables(ProtocolIPv4), failMultiTable: true}
	ipt := NewIPTables(rec)

	if err := ipt.RegisterChainOverride("filter", "MT_a2069f35"); err != nil {
		t.Fatal(err)
	}
	if err := ipt.Append("filter", "MT_a2069f35", "-m", "set", "--match-set", "mt_a2069f35_4", "dst", "-j", "ACCEPT"); err != nil {
		t.Fatal(err)
	}
	if err := ipt.RegisterChainOverride("nat", "MT_d0bb14fb"); err != nil {
		t.Fatal(err)
	}
	if err := ipt.Append("nat", "MT_d0bb14fb", "-m", "set", "--match-set", "mt_d0bb14fb_4", "dst", "-j", "MASQUERADE"); err != nil {
		t.Fatal(err)
	}

	if err := ipt.Commit(); err != nil {
		t.Fatalf("фолбэк должен спасать таблицы по одной: %v", err)
	}
	// вызов 1 - общий поток (отказ), 2 и 3 - filter и nat по отдельности
	if len(rec.calls) != 3 {
		t.Fatalf("restore вызовов: %d, ждём 3 (общий + 2 таблицы)", len(rec.calls))
	}
	if countCommits(rec.calls[0]) != 2 {
		t.Fatalf("первый вызов должен нести обе таблицы: %q", rec.calls[0])
	}
	if !rec.ChainExists("filter", "MT_a2069f35") {
		t.Fatal("filter не доехал в фолбэке")
	}
	if !rec.ChainExists("nat", "MT_d0bb14fb") {
		t.Fatal("nat не доехал в фолбэке")
	}
	// следующая Commit чистая (дифф пустой) - ошибок не рождает
	if err := ipt.Commit(); err != nil {
		t.Fatalf("повторный коммит должен проходить: %v", err)
	}
}

// Честная ошибка: если таблица не проходит даже потаблично - Commit
// возвращает ошибку с именем таблицы (а не молча теряет).
func TestCommitFallbackReportsFailedTable(t *testing.T) {
	rec := &recordingFake{FakeIPTables: NewFakeIPTables(ProtocolIPv4), failAll: true}
	ipt := NewIPTables(rec)
	if err := ipt.RegisterChainOverride("filter", "MT_x"); err != nil {
		t.Fatal(err)
	}
	if err := ipt.Append("filter", "MT_x", "-j", "ACCEPT"); err != nil {
		t.Fatal(err)
	}
	err := ipt.Commit()
	if err == nil {
		t.Fatal("упорный отказ должен возвращать ошибку")
	}
	if !strings.Contains(err.Error(), "table filter") {
		t.Fatalf("ошибка должна называть таблицу: %v", err)
	}
}

// Кламп -I: живой restore (1.4.21) отвергает номер за пределами цепочки -
// в потоке должен оказаться зажатый номер, а не исходный.
func TestChainPatchInsertClampedInStream(t *testing.T) {
	rec := &recordingFake{FakeIPTables: NewFakeIPTables(ProtocolIPv4)}
	rec.SetInitialRules("nat", "PREROUTING", [][]string{
		{"-j", "NDM_A"}, {"-j", "NDM_B"},
	})
	ipt := NewIPTables(rec)
	if err := ipt.RegisterChainPatch("nat", "PREROUTING"); err != nil {
		t.Fatal(err)
	}
	// номер 100 при живых двух правилах: реальный restore ответил бы
	// "line number out of range" и унёс COMMIT
	if err := ipt.Insert("nat", "PREROUTING", 100, "-j", "MT_DNSOR"); err != nil {
		t.Fatal(err)
	}
	if err := ipt.Commit(); err != nil {
		t.Fatalf("клёмпнутый -I должен проходить: %v", err)
	}
	var insertLine []byte
	for _, call := range rec.calls {
		for _, line := range bytes.Split(call, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("-I PREROUTING")) {
				insertLine = line
			}
		}
	}
	if insertLine == nil {
		t.Fatal("-I не ушёл в поток")
	}
	if !bytes.Contains(insertLine, []byte("-I PREROUTING 3 ")) {
		t.Fatalf("-I должен быть зажат к 3 (живых правил 2): %q", insertLine)
	}
}

// invalidOption - обе формулировки сборок без -w: iptables legacy
// ("invalid option") и busybox/другие ("unrecognized option") - живые
// случаи: Кинетик и OpenWrt 24.10 (инцидент rev18 на 0.62).
func TestInvalidOptionPhrases(t *testing.T) {
	cases := map[string]bool{
		"iptables-save: invalid option -- 'w'":          true,
		"iptables-save: unrecognized option: w":          true,
		"Look at manual page `iptables-save.8'":         false,
		"iptables-restore: line 70 failed":               false,
		"":                                               false,
	}
	for stderr, want := range cases {
		if got := invalidOption(stderr); got != want {
			t.Fatalf("invalidOption(%q) = %v, ждём %v", stderr, got, want)
		}
	}
}
