package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"magitrickle"
	"magitrickle/api/v1"
	"magitrickle/api/v1/types"
	"magitrickle/constant"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func setupHTTP(a *magitrickle.App, rootRouter chi.Router, errChan chan error) (*http.Server, error) {
	address := fmt.Sprintf("%s:%d",
		a.Config().HTTPWeb.Host.Address,
		a.Config().HTTPWeb.Host.Port,
	)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen error: %v", err)
	}

	srv := &http.Server{Handler: rootRouter}

	go func() {
		if e := srv.Serve(listener); e != nil && e != http.ErrServerClosed {
			errChan <- e
		}
		_ = listener.Close()
	}()

	srv.Addr = listener.Addr().String()

	return srv, nil
}

func TestIntegration(t *testing.T) {
	core := magitrickle.New()

	errChan := make(chan error, 1)

	rootRouter := chi.NewRouter()
	rootRouter.Use(middleware.Recoverer)

	h := v1.NewHandler(core)
	apiRouter := v1.NewRouter(core)

	apiRouter.Get("/groups", h.GetGroups)
	apiRouter.Post("/groups", h.CreateGroup)

	rootRouter.Mount("/api/v1", apiRouter)

	srv, err := setupHTTP(core, rootRouter, errChan)
	if err != nil {
		t.Fatalf("setupHTTP error: %v", err)
	}

	baseURL := fmt.Sprintf("http://%s/api/v1", srv.Addr)
	t.Logf("Server started at %s", baseURL)

	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		})
	}
	defer shutdown()

	go func() {
		if e := <-errChan; e != nil {
			t.Logf("server error: %v", e)
			shutdown()
		}
	}()

	//-----------//
	// Тесты API //
	//-----------//

	t.Run("CheckGroupsInitially", func(t *testing.T) {
		resp, body := doRequest(t, http.MethodGet, baseURL+"/groups", nil)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("GET /groups => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var gr types.GroupsRes
		mustDecode(t, body, &gr)

		if gr.Groups == nil {
			t.Log("Groups is nil => нет групп")
		} else {
			t.Logf("We have %d groups", len(*gr.Groups))
		}
	})

	t.Run("GetVersion", func(t *testing.T) {
		resp, body := doRequest(t, http.MethodGet, baseURL+"/version", nil)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("GET /version => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var vr types.VersionRes
		mustDecode(t, body, &vr)
		if vr.Version == "" {
			t.Fatalf("version is empty")
		}
		if vr.Version != constant.Version {
			t.Errorf("version mismatch: got %q, want constant.Version %q", vr.Version, constant.Version)
		}
		t.Logf("version: %s", vr.Version)
	})

	t.Run("CreateGroup", func(t *testing.T) {
		req := types.GroupReq{Name: "TestGroup1"}
		payload, _ := json.Marshal(req)

		resp, body := doRequest(t, http.MethodPost, baseURL+"/groups", payload)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("POST /groups => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var newGrp types.GroupRes
		mustDecode(t, body, &newGrp)

		if newGrp.Name != "TestGroup1" {
			t.Errorf("Expected group name=TestGroup1, got %s", newGrp.Name)
		}
		t.Logf("Created group with ID=%v", newGrp.ID)
	})

	t.Run("CreateGroupWithSources", func(t *testing.T) {
		req := types.GroupReq{
			Name:      "TestGroupSources",
			Interface: "nwg0",
			Sources:   []string{"192.168.1.50", "10.0.0.0/24"},
		}
		payload, _ := json.Marshal(req)

		resp, body := doRequest(t, http.MethodPost, baseURL+"/groups", payload)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("POST /groups (sources) => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var newGrp types.GroupRes
		mustDecode(t, body, &newGrp)
		if len(newGrp.Sources) != 2 || newGrp.Sources[0] != "192.168.1.50" || newGrp.Sources[1] != "10.0.0.0/24" {
			t.Fatalf("sources not echoed: %v", newGrp.Sources)
		}

		// кривой источник -> 400, группа не создаётся
		bad := types.GroupReq{Name: "TestGroupBadSource", Interface: "nwg0", Sources: []string{"not-an-ip"}}
		payload, _ = json.Marshal(bad)
		resp, body = doRequest(t, http.MethodPost, baseURL+"/groups", payload)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("POST /groups (bad source) => %d, want 400. Body: %s", resp.StatusCode, string(responseData))
		}
	})
}

func doRequest(t *testing.T, method, url string, data []byte) (*http.Response, io.ReadCloser) {
	t.Helper()
	var body io.Reader
	if data != nil {
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("http.NewRequest failed: %v", err)
	}
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s error: %v", method, url, err)
	}

	return resp, resp.Body
}

func mustDecode(t *testing.T, r io.Reader, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
}

// rev14: PUT /dns/upstreams с health - частичный патч доезжает до модели
// (проверяем через Config(): холодный App отдаёт пустой снапшот);
// невалидные диапазоны = 400; upstreams отсутствует = список не трогать
func TestDnsUpstreamsPutHealth(t *testing.T) {
	core := magitrickle.New()
	errChan := make(chan error, 1)
	rootRouter := chi.NewRouter()
	rootRouter.Use(middleware.Recoverer)
	rootRouter.Mount("/api/v1", v1.NewRouter(core))
	srv, err := setupHTTP(core, rootRouter, errChan)
	if err != nil {
		t.Fatalf("setupHTTP error: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s/api/v1", srv.Addr)
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		})
	}
	defer shutdown()
	go func() {
		if e := <-errChan; e != nil {
			shutdown()
		}
	}()

	url := baseURL + "/dns/upstreams"
	nBefore := len(core.Config().DNSProxy.UpstreamList())
	if nBefore == 0 {
		t.Fatalf("дефолтный список апстримов пуст")
	}

	// health-only запись (без upstreams): частичный патч
	payload := `{"health":{"enabled":false,"intervalSec":30,"restoreGapSec":60}}`
	resp, body := doRequest(t, http.MethodPut, url, []byte(payload))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(body)
		t.Fatalf("PUT health-only => %d: %s", resp.StatusCode, string(b))
	}
	cfg := core.Config().DNSProxy
	if cfg.Health.Enabled || cfg.Health.Interval != 30*time.Second || cfg.Health.RestoreGap != time.Minute {
		t.Fatalf("health-патч не применился: %+v", cfg.Health)
	}
	if cfg.Health.Timeout != 2*time.Second || cfg.Health.FailCycles != 3 || cfg.Health.RestoreCycles != 2 {
		t.Fatalf("nil-поля патча трогать нельзя: %+v", cfg.Health)
	}
	if got := len(cfg.UpstreamList()); got != nBefore {
		t.Fatalf("health-only запись тронула список: %d -> %d", nBefore, got)
	}

	// upstreams + health вместе
	payload = `{"upstreams":["8.8.8.8","tls://1.1.1.1"],"health":{"intervalSec":60,"failCycles":5,"restoreCycles":4,"timeoutSec":3}}`
	resp, body = doRequest(t, http.MethodPut, url, []byte(payload))
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(body)
		t.Fatalf("PUT список+health => %d: %s", resp.StatusCode, string(b))
	}
	resp.Body.Close()
	cfg = core.Config().DNSProxy
	list := cfg.UpstreamList()
	if len(list) != 2 || list[0].Address != "8.8.8.8" || list[0].Port != 53 || list[1].Address != "tls://1.1.1.1:853" {
		t.Fatalf("список не заменился: %+v", list)
	}
	if cfg.Health.Interval != time.Minute || cfg.Health.FailCycles != 5 || cfg.Health.RestoreCycles != 4 || cfg.Health.Timeout != 3*time.Second {
		t.Fatalf("полный health-патч: %+v", cfg.Health)
	}

	// невалидные диапазоны -> 400
	for _, bad := range []string{
		`{"health":{"intervalSec":4}}`,
		`{"health":{"intervalSec":301}}`,
		`{"health":{"timeoutSec":0}}`,
		`{"health":{"timeoutSec":11}}`,
		`{"health":{"failCycles":0}}`,
		`{"health":{"restoreCycles":21}}`,
		`{"health":{"restoreGapSec":3601}}`,
	} {
		resp, body = doRequest(t, http.MethodPut, url, []byte(bad))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PUT %s => %d, хочу 400", bad, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// кривой адрес в списке -> 400 (старый контракт сохранён)
	resp, body = doRequest(t, http.MethodPut, url, []byte(`{"upstreams":[]}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT пустой список => %d, хочу 400", resp.StatusCode)
	}
}
