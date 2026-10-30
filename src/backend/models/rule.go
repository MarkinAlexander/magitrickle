package models

import (
	"regexp"
	"sync"

	"magitrickle/utils/intID"

	"github.com/IGLOU-EU/go-wildcard/v2"
	"github.com/dlclark/regexp2"
)

const (
	RuleTypeDomain    string = "domain"
	RuleTypeNamespace string = "namespace"
	RuleTypeWildcard  string = "wildcard"
	RuleTypeRegEx     string = "regex"
	RuleTypeSubnet    string = "subnet"
	RuleTypeSubnet6   string = "subnet6"
)

type Rule struct {
	ID     intID.ID `yaml:"id"`
	Name   string   `yaml:"name"`
	Type   string   `yaml:"type"`
	Rule   string   `yaml:"rule"`
	Enable bool     `yaml:"enable"`

	compileOnce sync.Once
	compileWait sync.WaitGroup
	compileErr  error
	compiled    func(string) bool
}

func (d *Rule) IsEnabled() bool {
	return d.Enable
}

func (d *Rule) Compile() error {
	d.compileOnce.Do(func() {
		d.compileWait.Add(1)
		defer d.compileWait.Done()

		switch d.Type {
		case RuleTypeRegEx:
			matcher, err := compileRegexMatcher(d.Rule)
			if err != nil {
				d.compileErr = err
			}
			d.compiled = matcher
		}
	})
	d.compileWait.Wait()
	return d.compileErr
}

// compileRegexMatcher строит матчер regex-правила. Первым пробуется
// stdlib RE2 (линейное время, без бэктрекинга; для DNS-матчинга это
// порядок быстрее - волны CPU на mipsle давал именно regexp2, профиль
// 96-док). IgnoreCase из regexp2 переводится в (?i). Паттерны с
// .NET-спецификой (lookaround, backreferences), которые RE2 не берёт,
// падают на regexp2 как раньше. Семантика на общем подмножестве
// синтаксиса совпадает (имена доменов без переводов строк).
func compileRegexMatcher(pattern string) (func(string) bool, error) {
	if re, err := regexp.Compile("(?i)" + pattern); err == nil {
		return re.MatchString, nil
	}
	re, err := regexp2.Compile(pattern, regexp2.IgnoreCase)
	if err != nil {
		return func(string) bool { return false }, err
	}
	return func(s string) bool {
		ok, _ := re.MatchString(s)
		return ok
	}, nil
}

func (d *Rule) IsMatch(domainName string) bool {
	switch d.Type {
	case RuleTypeDomain:
		return domainName == d.Rule

	case RuleTypeNamespace:
		if domainName == d.Rule {
			return true
		}

		ruleLen := len(d.Rule)
		domainLen := len(domainName)
		if domainLen < ruleLen+1 {
			return false
		}
		return domainName[domainLen-ruleLen-1] == '.' && domainName[domainLen-ruleLen:] == d.Rule

	case RuleTypeWildcard:
		return wildcard.Match(d.Rule, domainName)

	case RuleTypeRegEx:
		err := d.Compile()
		if err != nil {
			return false
		}
		return d.compiled(domainName)

	case RuleTypeSubnet, RuleTypeSubnet6:
		return false
	}
	return false
}
