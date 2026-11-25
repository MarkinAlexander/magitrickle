package magitrickle

import (
	"reflect"
	"testing"
)

func TestResolveLinks(t *testing.T) {
	has := func(names ...string) func(string) bool {
		set := map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		return func(name string) bool { return set[name] }
	}
	cases := []struct {
		name    string
		cfg     []string
		exists  []string
		fb      []string
		want    []string
		absent  []string
		fbCalls int
	}{
		{name: "all present: fallback not asked", cfg: []string{"br0", "br0", "eth1"}, exists: []string{"br0", "eth1"}, want: []string{"br0", "eth1"}},
		{name: "keenetic default on openwrt", cfg: []string{"br0"}, exists: []string{"br-lan", "eth0"}, fb: []string{"br-lan", "eth0"}, want: []string{"br-lan"}, absent: []string{"br0"}, fbCalls: 1},
		{name: "present links kept, missing replaced", cfg: []string{"eth1", "br0"}, exists: []string{"eth1", "br-lan"}, fb: []string{"br-lan"}, want: []string{"eth1", "br-lan"}, absent: []string{"br0"}, fbCalls: 1},
		{name: "fallback already listed", cfg: []string{"br0", "br-lan"}, exists: []string{"br-lan"}, fb: []string{"br-lan"}, want: []string{"br-lan"}, absent: []string{"br0"}, fbCalls: 1},
		{name: "nothing found: error path of the caller", cfg: []string{"br0"}, fb: []string{"br-lan"}, want: nil, absent: []string{"br0"}, fbCalls: 1},
		{name: "no fallback candidates", cfg: []string{"br0"}, want: nil, absent: []string{"br0"}, fbCalls: 1},
		{name: "empty config: untouched", cfg: []string{}, fb: []string{"br-lan"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			got, absent := resolveLinks(c.cfg, has(c.exists...), func() []string { calls++; return c.fb })
			if !reflect.DeepEqual(got, c.want) || !reflect.DeepEqual(absent, c.absent) || calls != c.fbCalls {
				t.Fatalf("got %v absent %v calls %d, want %v absent %v calls %d", got, absent, calls, c.want, c.absent, c.fbCalls)
			}
		})
	}
}

func TestOptionList(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"br-lan\n", []string{"br-lan"}},
		{"eth0 eth1 ", []string{"eth0", "eth1"}},
		{"  ", nil},
		{"", nil},
	} {
		got := optionList(c.in)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}
