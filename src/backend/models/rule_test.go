package models

import (
	"testing"

	"github.com/dlclark/regexp2"
)

func TestRule_IsMatch_Domain(t *testing.T) {
	rule := &Rule{
		Type: RuleTypeDomain,
		Rule: "example.com",
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"noexample.com", false},
		{"sub.example.com", false},
		{"example.com.ru", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := rule.IsMatch(tt.domain); got != tt.want {
			t.Errorf("Rule{Type: %q, Rule: %q}.IsMatch(%q) = %v, want %v",
				rule.Type, rule.Rule, tt.domain, got, tt.want)
		}
	}
}

func TestRule_IsMatch_Namespace(t *testing.T) {
	rule := &Rule{
		Type: RuleTypeNamespace,
		Rule: "example.com",
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
		{"noexample.com", false},
		{"notexample.com", false},
		{"example.com.ru", false},
		{"fakeexample.com", false},
		{"", false},
		{"com", false},
		{".example.com", true},
	}

	for _, tt := range tests {
		if got := rule.IsMatch(tt.domain); got != tt.want {
			t.Errorf("Rule{Type: %q, Rule: %q}.IsMatch(%q) = %v, want %v",
				rule.Type, rule.Rule, tt.domain, got, tt.want)
		}
	}
}

func TestRule_IsMatch_Namespace_Short(t *testing.T) {
	rule := &Rule{
		Type: RuleTypeNamespace,
		Rule: "ru",
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"ru", true},
		{"example.ru", true},
		{"sub.example.ru", true},
		{"ru.com", false},
		{"", false},
		{"r", false},
	}

	for _, tt := range tests {
		if got := rule.IsMatch(tt.domain); got != tt.want {
			t.Errorf("Rule{Type: %q, Rule: %q}.IsMatch(%q) = %v, want %v",
				rule.Type, rule.Rule, tt.domain, got, tt.want)
		}
	}
}

func TestRule_IsMatch_Wildcard(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{"ex*le.com", "example.com", true},
		{"ex*le.com", "exle.com", true},
		{"ex*le.com", "noexample.com", false},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "example.com", false},
		{"*example*", "example.com", true},
		{"*example*", "myexamplesite.ru", true},
		{"test*.com", "test123.com", true},
		{"test??.com", "test12.com", true},
		{"test??.com", "test123.com", false},
		{"test.com", "test12.com", false},
	}

	for _, tt := range tests {
		rule := &Rule{
			Type: RuleTypeWildcard,
			Rule: tt.pattern,
		}
		if got := rule.IsMatch(tt.domain); got != tt.want {
			t.Errorf("Rule{Type: %q, Rule: %q}.IsMatch(%q) = %v, want %v",
				rule.Type, rule.Rule, tt.domain, got, tt.want)
		}
	}
}

func TestRule_IsMatch_RegEx(t *testing.T) {
	tests := []struct {
		pattern string
		domain  string
		want    bool
	}{
		{"^ex[apm]{3}le.com$", "example.com", true},
		{"^ex[apm]{3}le.com$", "exapple.com", true},
		{"^ex[apm]{3}le.com$", "noexample.com", false},
		{"example", "example.com", true},     // частичное совпадение
		{"^example$", "example.com", false},  // полное совпадение
		{"(?i)EXAMPLE", "example.com", true}, // case insensitive (уже включено)
		{"\\d+\\.example", "123.example", true},
	}

	for _, tt := range tests {
		rule := &Rule{
			Type: RuleTypeRegEx,
			Rule: tt.pattern,
		}
		if got := rule.IsMatch(tt.domain); got != tt.want {
			t.Errorf("Rule{Type: %q, Rule: %q}.IsMatch(%q) = %v, want %v",
				rule.Type, rule.Rule, tt.domain, got, tt.want)
		}
	}
}

func TestRule_IsMatch_RegEx_Invalid(t *testing.T) {
	rule := &Rule{
		Type: RuleTypeRegEx,
		Rule: "[invalid(regex",
	}

	// Невалидный regex не должен матчить ничего
	if rule.IsMatch("anything") {
		t.Error("Invalid regex should not match anything")
	}

	// Проверяем что Compile возвращает ошибку
	if err := rule.Compile(); err == nil {
		t.Error("Compile() should return error for invalid regex")
	}
}

func TestRule_IsMatch_UnknownType(t *testing.T) {
	rule := &Rule{
		Type: "unknown",
		Rule: "example.com",
	}

	if rule.IsMatch("example.com") {
		t.Error("Unknown rule type should not match anything")
	}
}

// Бенчмарки

func BenchmarkRule_IsMatch_Domain(b *testing.B) {
	rule := &Rule{Type: RuleTypeDomain, Rule: "example.com"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.IsMatch("example.com")
	}
}

func BenchmarkRule_IsMatch_Namespace(b *testing.B) {
	rule := &Rule{Type: RuleTypeNamespace, Rule: "example.com"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.IsMatch("sub.example.com")
	}
}

func BenchmarkRule_IsMatch_Namespace_NoMatch(b *testing.B) {
	rule := &Rule{Type: RuleTypeNamespace, Rule: "example.com"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.IsMatch("notexample.com")
	}
}

func BenchmarkRule_IsMatch_Wildcard(b *testing.B) {
	rule := &Rule{Type: RuleTypeWildcard, Rule: "*.example.com"}
	rule.Compile()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.IsMatch("sub.example.com")
	}
}

func BenchmarkRule_IsMatch_Wildcard_NoCompile(b *testing.B) {
	rule := &Rule{Type: RuleTypeWildcard, Rule: "*.example.com"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.IsMatch("sub.example.com")
	}
}

func BenchmarkRule_IsMatch_RegEx(b *testing.B) {
	rule := &Rule{Type: RuleTypeRegEx, Rule: "^.*\\.example\\.com$"}
	rule.Compile()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.IsMatch("sub.example.com")
	}
}

func BenchmarkRule_IsMatch_RegEx_NoCompile(b *testing.B) {
	rule := &Rule{Type: RuleTypeRegEx, Rule: "^.*\\.example\\.com$"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.IsMatch("sub.example.com")
	}
}

// compileRegexMatcher: RE2 первым (линейное время), regexp2 - фолбэк для
// .NET-специфики; семантика IgnoreCase сохраняется (волны CPU, 96-док).
func TestCompileRegexRE2First(t *testing.T) {
	m, err := compileRegexMatcher(`^.*---sn-[a-z0-9-]{2,10}\.googlevideo\.com$`)
	if err != nil {
		t.Fatalf("RE2-совместимый паттерн не скомпилировался: %v", err)
	}
	if !m("v1---sn-ojhgnc-5q.googlevideo.com") {
		t.Fatal("RE2-матчер не сработал на совпадении")
	}
	if m("example.com") {
		t.Fatal("RE2-матчер сработал на несовпадении")
	}
}

func TestCompileRegexFallbackRegexp2(t *testing.T) {
	// lookbehind RE2 не берёт - должен уйти в regexp2 без ошибки
	m, err := compileRegexMatcher(`(?<=^x)abc`)
	if err != nil {
		t.Fatalf("фолбэк regexp2 не сработал: %v", err)
	}
	if !m("xabc") {
		t.Fatal("regexp2-матчер не сработал")
	}
}

func TestCompileRegexInvalidBothEngines(t *testing.T) {
	if _, err := compileRegexMatcher(`*[`); err == nil {
		t.Fatal("битый паттерн должен давать ошибку")
	}
}

func TestRegexRuleIgnoreCaseParity(t *testing.T) {
	rule := &Rule{Type: RuleTypeRegEx, Rule: `^.*\.GOOGLEVideo\.COM$`}
	if err := rule.Compile(); err != nil {
		t.Fatal(err)
	}
	if !rule.IsMatch("sub.googLEvideo.Com") {
		t.Fatal("IgnoreCase потерян")
	}
	if rule.IsMatch("sub.example.com") {
		t.Fatal("ложное совпадение")
	}
}

// Паритет вердиктов RE2 против regexp2 на правилах реального конфига
// (общее подмножество синтаксиса должно матчиться одинаково).
func TestRegexRuleRE2ParityWithRegexp2(t *testing.T) {
	patterns := []string{
		`.*---sn-ojhgnc-5q\.googlevideo\.com$`,
		`^(www|maps)\.(yandex|google)\.[a-z]{2,}$`,
		`^[a-z0-9-]+\.cdn-video\.example\.com`,
		`(\.youtube\.com$)|(\.ytimg\.com$)`,
		`^r[0-9]{1,3}---sn-.*\.googlevideo\.com$`,
	}
	names := []string{
		"v1---sn-ojhgnc-5q.googlevideo.com",
		"r2---sn-abcd.googlevideo.com",
		"www.yandex.ru",
		"maps.google.com",
		"foo.cdn-video.example.com",
		"bar.youtube.com",
		"i.ytimg.com",
		"example.org",
	}
	for _, p := range patterns {
		m, err := compileRegexMatcher(p)
		if err != nil {
			t.Fatalf("%q: %v", p, err)
		}
		ref, refErr := regexp2.Compile(p, regexp2.IgnoreCase)
		if refErr != nil {
			t.Fatalf("%q: regexp2 отказался: %v", p, refErr)
		}
		for _, n := range names {
			want, _ := ref.MatchString(n)
			if got := m(n); got != want {
				t.Fatalf("%q на %q: RE2=%v regexp2=%v", p, n, got, want)
			}
		}
	}
}
