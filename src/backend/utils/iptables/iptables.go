package iptables

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Protocol byte

const (
	ProtocolIPv4 Protocol = 0
	ProtocolIPv6 Protocol = 1
)

var (
	ErrChainNotInitialized = errors.New("chain not initialized")
)

type IPTables struct {
	rules      map[string]map[string]chain
	executable Executable
	sync       sync.RWMutex
}

// tableRange - границы потока одной таблицы в буфере коммита
// (для потабличного фолбэка при отказе рестора)
type tableRange struct {
	name  []byte
	start int
}

func NewIPTables(executable Executable) *IPTables {
	return &IPTables{
		rules:      make(map[string]map[string]chain),
		executable: executable,
	}
}

func (ipt *IPTables) Proto() Protocol {
	return ipt.executable.Proto()
}

func (ipt *IPTables) RegisterChainDelete(table, chainName string) error {
	ipt.sync.Lock()
	defer ipt.sync.Unlock()

	if _, ok := ipt.rules[table]; !ok {
		ipt.rules[table] = make(map[string]chain)
	}
	ipt.rules[table][chainName] = &chainDelete{}
	return nil
}

func (ipt *IPTables) RegisterChainPatch(table, chainName string) error {
	ipt.sync.Lock()
	defer ipt.sync.Unlock()

	if _, ok := ipt.rules[table]; !ok {
		ipt.rules[table] = make(map[string]chain)
	}
	ipt.rules[table][chainName] = &chainPatch{}
	return nil
}

func (ipt *IPTables) RegisterChainOverride(table, chainName string) error {
	ipt.sync.Lock()
	defer ipt.sync.Unlock()

	if _, ok := ipt.rules[table]; !ok {
		ipt.rules[table] = make(map[string]chain)
	}
	ipt.rules[table][chainName] = &chainOverride{}
	return nil
}

func (ipt *IPTables) Append(table, chain string, ruleArgs ...string) error {
	ipt.sync.RLock()
	defer ipt.sync.RUnlock()

	if ipt.rules[table] == nil || ipt.rules[table][chain] == nil {
		return ErrChainNotInitialized
	}

	return ipt.rules[table][chain].Append(ruleFromStrings(ruleArgs))
}

func (ipt *IPTables) Insert(table, chain string, ruleNum int, ruleArgs ...string) error {
	ipt.sync.RLock()
	defer ipt.sync.RUnlock()

	if ipt.rules[table] == nil || ipt.rules[table][chain] == nil {
		return ErrChainNotInitialized
	}

	return ipt.rules[table][chain].Insert(ruleNum, ruleFromStrings(ruleArgs))
}

func (ipt *IPTables) Delete(table, chain string, ruleArgs ...string) error {
	ipt.sync.RLock()
	defer ipt.sync.RUnlock()

	if ipt.rules[table] == nil || ipt.rules[table][chain] == nil {
		return ErrChainNotInitialized
	}

	return ipt.rules[table][chain].Delete(ruleFromStrings(ruleArgs))
}

func (ipt *IPTables) GetCurrentRules() (map[string]map[string][]Rule, error) {
	rules := make(map[string]map[string][]Rule)

	data, err := ipt.executable.Save()
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(data, []byte("\n"))
	var currentTable string
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		switch line[0] {
		case '*':
			currentTable = string(line[1:])
			if rules[currentTable] == nil {
				rules[currentTable] = make(map[string][]Rule)
			}

		case ':':
			// Формат: ":CHAIN POLICY [packets:bytes]"
			// Найдём первый пробел для получения имени chain
			spaceIdx := bytes.IndexByte(line[1:], ' ')
			var chainName string
			if spaceIdx == -1 {
				chainName = string(line[1:])
			} else {
				chainName = string(line[1 : 1+spaceIdx])
			}
			if chainName == "" {
				return nil, fmt.Errorf("invalid chain declaration")
			}
			if rules[currentTable][chainName] == nil {
				rules[currentTable][chainName] = []Rule{}
			}

		case '-':
			if currentTable == "" {
				return nil, fmt.Errorf("rule outside of table")
			}

			fields := splitFields(line)
			if len(fields) < 2 {
				return nil, fmt.Errorf("invalid rule: %q", line)
			}

			chainName := string(fields[1])
			if len(fields[0]) < 2 {
				return nil, fmt.Errorf("invalid rule command: %q", fields[0])
			}
			switch fields[0][1] {
			case 'A': // Append
				// fields[2:] - правило без оператора
				rules[currentTable][chainName] = append(rules[currentTable][chainName], fields[2:])

			default:
				return nil, fmt.Errorf("unknown iptables command %q", fields[0])
			}

		case '#':
			continue

		case 'C':
			currentTable = ""

		default:
			return nil, fmt.Errorf("unknown iptables input %q", line)
		}
	}

	return rules, nil
}

// splitFields разбивает строку на поля по пробелам, возвращая срезы оригинального буфера
func splitFields(data []byte) [][]byte {
	var fields [][]byte
	start := -1
	for i, b := range data {
		if b == ' ' || b == '\t' {
			if start >= 0 {
				fields = append(fields, data[start:i])
				start = -1
			}
		} else {
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		fields = append(fields, data[start:])
	}
	return fields
}

func (ipt *IPTables) Commit() (err error) {
	ipt.sync.RLock()
	defer ipt.sync.RUnlock()

	buf := new(bytes.Buffer)
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		iptType := "iptables"
		if ipt.Proto() == ProtocolIPv6 {
			iptType = "ip6tables"
		}
		var logEvent *zerolog.Event
		if err != nil {
			logEvent = log.Error().Err(err)
		} else {
			logEvent = log.Trace()
		}
		logEvent.Dur("elapsed_ms", elapsed).Str("type", iptType).Bytes("buf", buf.Bytes()).Msg("iptables commit")
	}()

	curRules, err := ipt.GetCurrentRules()
	if err != nil {
		return err
	}

	// ipset sets are family-bound: a rule referencing an IPv4 set
	// must never reach the IPv6 restore stream and vice versa,
	// iptables-restore rejects such a commit as a whole ("The
	// protocol family of set ... is not applicable"). Drop those
	// commands instead of failing the entire batch. ipset names
	// embed the family suffix: "_4" for IPv4, "_6" for IPv6
	// (see netfilterTools.IPSet naming).
	oppositeSuffix := []byte("_4")
	if ipt.Proto() == ProtocolIPv4 {
		oppositeSuffix = []byte("_6")
	}
	dropCrossFamily := func(rule Rule) bool {
		for _, part := range rule {
			if bytes.HasSuffix(part, oppositeSuffix) {
				return true
			}
		}
		return false
	}
	ruleDropped := 0
	// Детерминированный порядок таблиц в потоке рестора: iptables-restore
	// применяет таблицы последовательно и падает на первой ошибке, поэтому
	// случайный порядок map давал недетерминированное частичное состояние
	// ("какие хуки выжили" менялось от попытки к попытке). Сортировка
	// даёт стабильный порядок (filter < mangle < nat) и воспроизводимые
	// отказы.
	tableNames := make([]string, 0, len(ipt.rules))
	for tableName := range ipt.rules {
		tableNames = append(tableNames, tableName)
	}
	slices.Sort(tableNames)
	// границы таблиц в буфере - для потабличного фолбэка при отказе рестора
	tableStarts := make([]tableRange, 0, len(tableNames))
	for _, tableName := range tableNames {
		table := ipt.rules[tableName]
		curTable := curRules[tableName]

		var tableExists bool
		tableNameBytes := []byte(tableName)

		commandsPrioritized := make(map[int8][]command)
		for chainName, chain := range table {
			chainNameBytes := []byte(chainName)
			var curChain []Rule
			if curTable[chainName] != nil {
				curChain = curTable[chainName]
			}
			commands, priority, err := chain.Compile(chainNameBytes, curChain)
			if err != nil {
				return err
			}
			if commandsPrioritized[int8(priority)] == nil {
				commandsPrioritized[int8(priority)] = make([]command, 0)
			}
			if len(commands) > 0 {
				if !tableExists {
					tableStarts = append(tableStarts, tableRange{name: tableNameBytes, start: buf.Len()})
					buf.WriteByte('*')
					buf.Write(tableNameBytes)
					buf.WriteByte('\n')
					tableExists = true
				}
				buf.WriteByte(':')
				buf.Write(chainNameBytes)
				buf.WriteString(" - [0:0]\n")
				commandsPrioritized[int8(priority)] = append(commandsPrioritized[int8(priority)], commands...)
			}
		}

		if !tableExists {
			continue
		}

		priorities := make([]int8, 0, len(commandsPrioritized))
		for priority := range commandsPrioritized {
			priorities = append(priorities, priority)
		}
		slices.Sort(priorities)

		for _, priority := range priorities {
			for _, cmd := range commandsPrioritized[priority] {
				switch cmd.Option {
				case optionAppend:
					if dropCrossFamily(cmd.Rule) {
						ruleDropped++
						continue
					}
					buf.WriteString("-A ")
					buf.Write(cmd.Chain)
					if len(cmd.Rule) > 0 {
						buf.WriteByte(' ')
						ruleWriteTo(buf, cmd.Rule)
					}
					buf.WriteByte('\n')
				case optionDelete:
					buf.WriteString("-D ")
					buf.Write(cmd.Chain)
					if len(cmd.Rule) > 0 {
						buf.WriteByte(' ')
						ruleWriteTo(buf, cmd.Rule)
					}
					buf.WriteByte('\n')
				case optionInsert:
					if dropCrossFamily(cmd.Rule) {
						ruleDropped++
						continue
					}
					buf.WriteString("-I ")
					buf.Write(cmd.Chain)
					buf.WriteByte(' ')
					buf.WriteString(strconv.Itoa(cmd.RuleNum))
					if len(cmd.Rule) > 0 {
						buf.WriteByte(' ')
						ruleWriteTo(buf, cmd.Rule)
					}
					buf.WriteByte('\n')
				case optionFlush:
					buf.WriteString("-F ")
					buf.Write(cmd.Chain)
					buf.WriteByte('\n')
				case optionDeleteChain:
					buf.WriteString("-X ")
					buf.Write(cmd.Chain)
					buf.WriteByte('\n')
				}
			}
		}
		buf.WriteString("COMMIT\n")
	}

	if buf.Len() == 0 {
		return nil
	}
	if ruleDropped > 0 {
		log.Warn().Int("count", ruleDropped).Msg("dropped cross-family ipset rules")
	}

	data := buf.Bytes()
	if err := ipt.executable.Restore(data); err != nil {
		// Потабличный фолбэк (Кинетик 03.11, инцидент геоблока): отказ
		// общего потока раньше хоронил ВСЕ таблицы - poisoned-хвост в одной
		// из них валил коммит каждого ретрая (reconcile бьётся каждые 30с
		// об одно и то же) до рестарта процесса. Теперь таблицы
		// пересылаются по одной: яд в mangle не мешает filter/nat, а
		// упавший поток целиком уходит в лог для диагностики. Таблицы,
		// применившиеся в общем потоке, могут дать дубликаты правил -
		// следующая Commit их снимает (точные -D / -F у override).
		log.Error().Err(err).Int("bytes", len(data)).Msg("iptables commit failed, retrying table-by-table")
		starts := make([]int, 0, len(tableStarts)+1)
		for _, tr := range tableStarts {
			starts = append(starts, tr.start)
		}
		starts = append(starts, len(data))
		var errs []error
		for i, tr := range tableStarts {
			table := data[starts[i]:starts[i+1]]
			if err := ipt.executable.Restore(table); err != nil {
				log.Error().Err(err).Str("table", string(tr.name)).Bytes("stream", table).
					Msg("iptables commit: table stream failed")
				errs = append(errs, fmt.Errorf("table %s: %w", tr.name, err))
			}
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
	}

	return nil
}
