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

	// waitMu/waitChecked/waitOK: поддержка -w (ожидание xtables-lock)
	// определяется один раз пробным запуском. Сборки без -w (Кинетик:
	// "iptables-restore: invalid option -- 'w'") навсегда уходят на
	// вызовы без флага; на поддерживающих -w рестор дожидается лока,
	// вместо потери коммита при занятом ndm-локе (инцидент 01.11).
	waitMu      sync.Mutex
	waitChecked bool
	waitOK      bool
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

// waitSupported возвращает true, если данная сборка iptables понимает -w.
// Проба - реальный вызов restore с пустым потоком (no-op): на сборках без
// -w он отвечает "invalid option -- 'w'" и флаг отключается навсегда.
func (ipt *realIPTables) waitSupported() bool {
	ipt.waitMu.Lock()
	defer ipt.waitMu.Unlock()
	if ipt.waitChecked {
		return ipt.waitOK
	}
	probe := exec.Command(ipt.restoreCmd, "--noflush", "-w", "5")
	probe.Stdin = bytes.NewReader(nil)
	var stderr bytes.Buffer
	probe.Stderr = &stderr
	err := probe.Run()
	ipt.waitOK = !(err != nil && invalidOption(stderr.String()))
	ipt.waitChecked = true
	if !ipt.waitOK {
		log.Warn().Str("cmd", ipt.restoreCmd).Msg("xtables -w not supported, lock-wait disabled")
	}
	return ipt.waitOK
}

func (ipt *realIPTables) disableWait() {
	ipt.waitMu.Lock()
	ipt.waitOK = false
	ipt.waitChecked = true
	ipt.waitMu.Unlock()
}

func invalidOption(stderr string) bool {
	return strings.Contains(stderr, "invalid option")
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
	if ipt.waitSupported() {
		out, stderr, err := ipt.save(true)
		if err == nil {
			return out, nil
		}
		if !invalidOption(stderr) {
			return nil, err
		}
		// сборка без -w (проба не успела) - откат и запоминание
		ipt.disableWait()
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
	if ipt.waitSupported() {
		stderr, err := ipt.restore(data, true)
		if err == nil {
			return nil
		}
		if !invalidOption(stderr) {
			return err
		}
		ipt.disableWait()
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
