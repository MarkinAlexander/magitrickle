package iptables

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

type realIPTables struct {
	saveCmd    string
	restoreCmd string
	proto      Protocol

	// waitMu + флаги: поддержка -w (ожидание xtables-lock) определяется
	// один раз пробными запусками, ОТДЕЛЬНО для save и restore - сборки
	// бывают несимметричны (OpenWrt 24.10: restore -w понимает, save -
	// нет; живой случай 03.11: MT падал на старте). Сборки без -w
	// (Кинетик: "iptables-save: invalid option -- 'w'") навсегда уходят
	// на вызовы без флага; на поддерживающих -w вызов дожидается лока
	// вместо потери коммита при занятом ndm-локе (инцидент 01.11).
	waitMu          sync.Mutex
	waitSaveOK      bool
	waitSaveChecked bool
	waitRestoreOK   bool
	waitRestoreOKCk bool
}

func NewRealIPTables() *realIPTables {
	return &realIPTables{
		saveCmd:    "iptables-save",
		restoreCmd: "iptables-restore",
		proto:      ProtocolIPv4,
	}
}

func NewRealIP6Tables() *realIPTables {
	return &realIPTables{
		saveCmd:    "ip6tables-save",
		restoreCmd: "ip6tables-restore",
		proto:      ProtocolIPv6,
	}
}

func (ipt *realIPTables) Proto() Protocol {
	return ipt.proto
}

// waitSupportedSave/waitSupportedRestore - пробы -w по каждой команде
// отдельно: проба - реальный вызов (save без аргументов / restore с
// пустым no-op потоком). На сборках без -w ответ "invalid option" или
// "unrecognized option" - формулировки зависят от варианта iptables
// (Кинетик vs OpenWrt busybox) - и флаг отключается навсегда.
func (ipt *realIPTables) waitSupportedSave() bool {
	ipt.waitMu.Lock()
	defer ipt.waitMu.Unlock()
	if ipt.waitSaveChecked {
		return ipt.waitSaveOK
	}
	var stderr bytes.Buffer
	probe := exec.Command(ipt.saveCmd, "-w", "5")
	probe.Stdout = &bytes.Buffer{}
	probe.Stderr = &stderr
	err := probe.Run()
	ipt.waitSaveOK = !(err != nil && invalidOption(stderr.String()))
	ipt.waitSaveChecked = true
	if !ipt.waitSaveOK {
		log.Warn().Str("cmd", ipt.saveCmd).Msg("xtables -w not supported for save, lock-wait disabled")
	}
	return ipt.waitSaveOK
}

func (ipt *realIPTables) waitSupportedRestore() bool {
	ipt.waitMu.Lock()
	defer ipt.waitMu.Unlock()
	if ipt.waitRestoreOKCk {
		return ipt.waitRestoreOK
	}
	probe := exec.Command(ipt.restoreCmd, "--noflush", "-w", "5")
	probe.Stdin = bytes.NewReader(nil)
	var stderr bytes.Buffer
	probe.Stderr = &stderr
	err := probe.Run()
	ipt.waitRestoreOK = !(err != nil && invalidOption(stderr.String()))
	ipt.waitRestoreOKCk = true
	if !ipt.waitRestoreOK {
		log.Warn().Str("cmd", ipt.restoreCmd).Msg("xtables -w not supported for restore, lock-wait disabled")
	}
	return ipt.waitRestoreOK
}

func (ipt *realIPTables) disableWaitSave() {
	ipt.waitMu.Lock()
	ipt.waitSaveOK = false
	ipt.waitSaveChecked = true
	ipt.waitMu.Unlock()
}

func (ipt *realIPTables) disableWaitRestore() {
	ipt.waitMu.Lock()
	ipt.waitRestoreOK = false
	ipt.waitRestoreOKCk = true
	ipt.waitMu.Unlock()
}

// invalidOption - сборка не знает флаг -w; варианты формулировок:
// iptables legacy "invalid option -- 'w'", busybox/другие варианты
// "unrecognized option: w" (живые случаи: Кинетик и OpenWrt 24.10)
func invalidOption(stderr string) bool {
	return strings.Contains(stderr, "invalid option") ||
		strings.Contains(stderr, "unrecognized option")
}

func (ipt *realIPTables) save(useWait bool) ([]byte, string, error) {
	var args []string
	if useWait {
		args = append(args, "-w", "5")
	}
	cmd := exec.Command(ipt.saveCmd, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, stderr.String(), fmt.Errorf(
			"iptables-save failed: %w: %s",
			err, stderr.String(),
		)
	}

	return stdout.Bytes(), stderr.String(), nil
}

func (ipt *realIPTables) Save() ([]byte, error) {
	if ipt.waitSupportedSave() {
		out, stderr, err := ipt.save(true)
		if err == nil {
			return out, nil
		}
		if !invalidOption(stderr) {
			return nil, err
		}
		// сборка без -w (проба не успела) - откат и запоминание
		ipt.disableWaitSave()
	}
	out, _, err := ipt.save(false)
	return out, err
}

func (ipt *realIPTables) restore(data []byte, useWait bool) (string, error) {
	var args []string
	if useWait {
		args = append(args, "-w", "5")
	}
	args = append(args, "--noflush")
	cmd := exec.Command(ipt.restoreCmd, args...)

	var stderr bytes.Buffer
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf(
			"iptables-restore failed: %w: %s%s",
			err, stderr.String(), restoreErrorContext(stderr.String(), data),
		)
	}

	return stderr.String(), nil
}

func (ipt *realIPTables) Restore(data []byte) error {
	if ipt.waitSupportedRestore() {
		stderr, err := ipt.restore(data, true)
		if err == nil {
			return nil
		}
		if !invalidOption(stderr) {
			return err
		}
		ipt.disableWaitRestore()
	}
	_, err := ipt.restore(data, false)
	return err
}

// restoreErrorContext extracts the failing stream line referenced by
// iptables-restore ("line N failed") so the error names the actual rule
// instead of an opaque line number.
func restoreErrorContext(stderr string, data []byte) string {
	m := regexp.MustCompile(`line (\d+) failed`).FindStringSubmatch(stderr)
	if m == nil {
		return ""
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 1 {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if n > len(lines) {
		return ""
	}
	return fmt.Sprintf(" (stream line %d: %q)", n, strings.TrimSpace(lines[n-1]))
}
