package v1

import (
	"reflect"
	"testing"

	"magitrickle/api/v1/types"
	"magitrickle/models"
	"magitrickle/utils/intID"
)

func TestGroupFromReqSources(t *testing.T) {
	id := intID.RandomID()

	group, err := GroupFromReq(types.GroupReq{
		ID:        &id,
		Name:      "test",
		Interface: "nwg0",
		Sources:   []string{"192.168.1.50", "10.0.0.0/24", " 2001:db8::/32 "},
	}, nil)
	if err != nil {
		t.Fatalf("valid sources rejected: %v", err)
	}
	want := []string{"192.168.1.50", "10.0.0.0/24", "2001:db8::/32"}
	if !reflect.DeepEqual(group.Sources, want) {
		t.Fatalf("sources: got %v, want %v", group.Sources, want)
	}

	// эхо в ответе
	res := RespFromGroup(group, false)
	if !reflect.DeepEqual(res.Sources, want) {
		t.Fatalf("RespFromGroup sources: got %v, want %v", res.Sources, want)
	}

	// отсутствие поля и пустой/пробельный список = без ограничения
	for name, srcs := range map[string][]string{
		"nil":      nil,
		"empty":    {},
		"blanks":   {"   ", ""},
		"mixedbad": {"   ", ""},
	} {
		g, err := GroupFromReq(types.GroupReq{Name: "x", Interface: "nwg0", Sources: srcs}, nil)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if g.Sources != nil {
			t.Fatalf("%s: sources not cleared: %v", name, g.Sources)
		}
	}
}

func TestGroupFromReqInvalidSource(t *testing.T) {
	for _, src := range []string{"not-an-ip", "192.168.1.999", "10.0.0.0/33", "example.com"} {
		if _, err := GroupFromReq(types.GroupReq{Name: "x", Interface: "nwg0", Sources: []string{src}}, nil); err == nil {
			t.Fatalf("invalid source %q accepted", src)
		}
	}
}

// localOnly: PUT-семантика - поле заменяется целиком, отсутствие = false
// (прежнее поведение с OUTPUT-прыжком); эхо в ответе
func TestGroupLocalOnlyRoundTrip(t *testing.T) {
	g, err := GroupFromReq(types.GroupReq{Name: "x", Interface: "nwg0", LocalOnly: true}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !g.LocalOnly {
		t.Fatalf("LocalOnly=true lost in GroupFromReq")
	}
	if res := RespFromGroup(g, false); !res.LocalOnly {
		t.Fatalf("LocalOnly=true lost in RespFromGroup")
	}

	// отсутствие поля на существующей группе снимает флаг (полная замена)
	existing := &models.Group{Name: "x", Interface: "nwg0", LocalOnly: true}
	g2, err := GroupFromReq(types.GroupReq{Name: "x", Interface: "nwg0"}, existing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g2.LocalOnly {
		t.Fatalf("LocalOnly not cleared on PUT without the field")
	}
}
