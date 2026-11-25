package magitrickle

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// resolveLinks - имена link, с которых собирать адреса локалки: отсутствующие
// заменяются первым существующим запасным. Порядок и повторы не меняются,
// absent - чего в системе не нашлось (для журнала); fallback зовётся, только
// когда он нужен. Ничего не нашлось вовсе - nil.
func resolveLinks(names []string, exists func(string) bool, fallback func() []string) (resolved, absent []string) {
	seen := make(map[string]bool, len(names)+1)
	for _, name := range names {
		if exists(name) {
			if !seen[name] {
				seen[name] = true
				resolved = append(resolved, name)
			}
			continue
		}
		absent = append(absent, name)
	}
	if len(absent) == 0 || len(names) == 0 {
		return resolved, nil
	}
	for _, name := range fallback() {
		if !seen[name] && exists(name) {
			resolved = append(resolved, name)
			break
		}
	}
	if len(resolved) == 0 {
		return nil, absent
	}
	return resolved, absent
}

// linkExists - есть ли интерфейс с таким именем.
func linkExists(name string) bool {
	_, err := netlink.LinkByName(name)
	return err == nil
}

// lanFallbackNames - чем подменить отсутствующий link. Дефолт кода - br0
// (Keenetic); пакет OpenWrt приносит br-lan, но config.yaml - conffile, и
// пустой после порчи opkg остаётся пустым и при переустановке (кейс 24.11:
// демон падал на старте с «failed to find link br0»). LAN OpenWrt спрашиваем
// у uci (24.10: network.lan.device, старые выпуски: network.lan.ifname,
// списком), затем - первый мост с адресом: секция lan может быть переименована.
func lanFallbackNames() []string {
	names := append(uciLanNames("network.lan.device"), uciLanNames("network.lan.ifname")...)
	links, err := netlink.LinkList()
	if err != nil {
		return names
	}
	for _, link := range links {
		if link.Type() != "bridge" {
			continue
		}
		if addrs, err := netlink.AddrList(link, nl.FAMILY_V4); err != nil || len(addrs) == 0 {
			continue
		}
		names = append(names, link.Attrs().Name)
	}
	return names
}

// uciLanNames - значение опции uci, разбитое по пробелам (список ifname
// печатается одной строкой); отсутствующая опция или uci - пусто.
func uciLanNames(key string) []string {
	return optionList(uciOption(key))
}

// uciOption - сырой вывод «uci get»; пустая строка - опции или uci нет.
func uciOption(key string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "uci", "-q", "get", key).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// optionList - слова из вывода uci (пробельные значения дают пустой список).
func optionList(out string) []string {
	return strings.Fields(out)
}
