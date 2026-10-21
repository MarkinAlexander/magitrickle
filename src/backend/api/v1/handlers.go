package v1

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"magitrickle/api/utils"
	"magitrickle/api/v1/types"
	"magitrickle/app"
	"magitrickle/constant"
	"magitrickle/models"
	"magitrickle/utils/intID"

	"github.com/rs/zerolog/log"
)

// Handler предоставляет набор методов для обработки API запросов.
type Handler struct {
	app app.Main
}

// NewHandler создаёт новый обработчик для API v1.
func NewHandler(a app.Main) *Handler {
	return &Handler{app: a}
}

func (h *Handler) userGroups() []app.RuleSet {
	return h.app.UserGroups()
}

// NetfilterDHook
//
//	@Summary		Хук эвента netfilter.d
//	@Description	Эмитирует хук эвента netfilter.d
//	@Tags			hooks
//	@Accept			json
//	@Produce		json
//	@Param			json	body	types.NetfilterDHookReq	true	"Тело запроса"
//	@Success		200
//	@Failure		400	{object}	types.ErrorRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/system/hooks/netfilterd [post]
func (h *Handler) NetfilterDHook(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.NetfilterDHookReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Debug().
		Str("type", req.Type).
		Str("table", req.Table).
		Msg("received netfilter.d event")
	err = h.app.ForceCommitIPTables()
	if err != nil {
		log.Error().Err(err).Msg("error fixing iptables after netfilter.d")
	}
}

// ListInterfaces
//
//	@Summary		Получить список интерфейсов
//	@Description	Возвращает список интерфейсов
//	@Tags			config
//	@Produce		json
//	@Success		200	{object}	types.InterfacesRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/system/interfaces [get]
func (h *Handler) ListInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces, err := h.app.ListInterfaces()
	if err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to get interfaces: %w", err).Error())
		return
	}

	res := make([]types.InterfaceRes, len(interfaces)+1)
	res[0] = types.InterfaceRes{ID: "blackhole"}
	for i, iface := range interfaces {
		res[i+1] = types.InterfaceRes{
			ID:   iface.ID,
			Name: iface.Name,
		}
	}

	utils.WriteJson(w, http.StatusOK, types.InterfacesRes{Interfaces: res})
}

// SaveConfig
//
//	@Summary		Сохранить конфигурацию
//	@Description	Сохраняет текущую конфигурацию в постоянную память
//	@Tags			config
//	@Produce		json
//	@Success		200
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/system/config/save [post]
func (h *Handler) SaveConfig(w http.ResponseWriter, r *http.Request) {
	if err := h.app.SaveConfig(); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save config: %v", err))
	}
}

// GetGroups
//
//	@Summary		Получить список групп
//	@Description	Возвращает список групп
//	@Tags			groups
//	@Produce		json
//	@Param			with_rules	query		bool	false	"Возвращать группы с их правилами"
//	@Success		200			{object}	types.GroupsRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups [get]
func (h *Handler) GetGroups(w http.ResponseWriter, r *http.Request) {
	withRules := r.URL.Query().Get("with_rules") == "true"
	appGroups := h.userGroups()
	modelGroups := make([]*models.Group, len(appGroups))
	for i, g := range appGroups {
		modelGroups[i] = g.Model()
	}
	utils.WriteJson(w, http.StatusOK, RespFromGroups(modelGroups, withRules))
}

// PutGroups
//
//	@Summary		Обновить список групп
//	@Description	Обновляет список групп
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.GroupsReq	true	"Тело запроса"
//	@Success		200		{object}	types.GroupsRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups [put]
func (h *Handler) PutGroups(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.GroupsReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Groups == nil {
		utils.WriteError(w, http.StatusBadRequest, "no groups in request")
		return
	}
	for _, g := range h.userGroups() {
		_ = g.Disable()
	}
	newGroups := make([]*models.Group, len(*req.Groups))
	for i, gReq := range *req.Groups {
		var existing *models.Group
		for _, g := range h.userGroups() {
			if gReq.ID != nil && g.Model().ID == *gReq.ID {
				existing = g.Model()
				break
			}
		}
		newGroups[i], err = GroupFromReq(gReq, existing)
		if err != nil {
			utils.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// Snapshot the old group models BEFORE ClearGroups: they are needed
	// to roll the runtime back if the new batch fails to come up,
	// otherwise a mid-batch failure leaves the runtime truncated.
	oldGroups := make([]*models.Group, 0, len(h.userGroups()))
	for _, g := range h.userGroups() {
		oldGroups = append(oldGroups, g.Model())
	}
	rollback := func() {
		h.app.ClearGroups()
		for _, g := range oldGroups {
			if err := h.app.AddGroup(g); err != nil {
				log.Error().Err(err).Msg("rollback: failed to restore group")
			}
		}
	}
	h.app.ClearGroups()
	// Continue past a failing group so the response names EVERY group that
	// could not come up (with its reason) instead of only the first one.
	// The rollback below still keeps the batch atomic.
	var failures []string
	for _, grp := range newGroups {
		if err := h.app.AddGroup(grp); err != nil {
			log.Error().Err(err).Str("group", grp.Name).Msg("bulk put: group failed")
			failures = append(failures, fmt.Sprintf("%q: %v", grp.Name, err))
			continue
		}
	}
	if len(failures) > 0 {
		log.Error().Msg("bulk put failed, rolling back")
		rollback()
		utils.WriteError(w, http.StatusInternalServerError,
			fmt.Sprintf("failed to enable %d group(s): %s", len(failures), strings.Join(failures, "; ")))
		return
	}
	if err := h.app.SyncSubscriptionRuleSets(); err != nil {
		log.Error().Err(err).Msg("subscription sync failed, rolling back")
		rollback()
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	utils.WriteJson(w, http.StatusOK, RespFromGroups(newGroups, true))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// CreateGroup
//
//	@Summary		Создать группу
//	@Description	Создает группу
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.GroupReq	true	"Тело запроса"
//	@Success		200		{object}	types.GroupRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups [post]
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.GroupReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	group, err := GroupFromReq(req, nil)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.app.AddGroup(group); err != nil {
		utils.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	utils.WriteJson(w, http.StatusOK, RespFromGroup(group, true))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// GetGroup
//
//	@Summary		Получить группу
//	@Description	Возвращает запрошенную группу
//	@Tags			groups
//	@Produce		json
//	@Param			groupID		path		string	true	"ID группы"
//	@Param			with_rules	query		bool	false	"Возвращать группу с её правилами"
//	@Success		200			{object}	types.GroupRes
//	@Failure		404			{object}	types.ErrorRes
//	@Failure		500			{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID} [get]
func (h *Handler) GetGroup(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	withRules := r.URL.Query().Get("with_rules") == "true"
	group := h.userGroups()[groupIdx].Model()
	utils.WriteJson(w, http.StatusOK, RespFromGroup(group, withRules))
}

// PutGroup
//
//	@Summary		Обновить группу
//	@Description	Обновляет запрошенную группу
//	@Tags			groups
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.GroupReq	true	"Тело запроса"
//	@Success		200		{object}	types.GroupRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID} [put]
func (h *Handler) PutGroup(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.GroupReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.userGroups()[groupIdx]

	enabled := groupWrapper.Enabled()
	if enabled {
		if err := groupWrapper.Disable(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to disable group: %v", err))
			return
		}
	}

	updatedGroup, err := GroupFromReq(req, groupWrapper.Model())
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Rebuild whenever the final model state says enabled, not only when
	// the runtime happened to be enabled before the request: GroupFromReq
	// defaults Enable to true, so a single PUT can flip a disabled group's
	// model to enabled. Skipping the rebuild left the model claiming
	// "enabled" with no iptables chain in the runtime until the next bulk
	// PUT or daemon restart.
	if updatedGroup.Enable {
		if err := groupWrapper.Enable(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to enable group: %v", err))
			return
		}
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	utils.WriteJson(w, http.StatusOK, RespFromGroup(updatedGroup, true))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// DeleteGroup
//
//	@Summary		Удалить группу
//	@Description	Удаляет запрошенную группу
//	@Tags			groups
//	@Produce		json
//	@Param			groupID	path	string	true	"ID группы"
//	@Param			save	query	bool	false	"Сохранить изменения в конфигурационный файл"
//	@Success		200
//	@Failure		404	{object}	types.ErrorRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID} [delete]
func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.userGroups()[groupIdx]
	if groupWrapper.Enabled() {
		if err := groupWrapper.Disable(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to disable group: %v", err))
			return
		}
	}
	h.app.RemoveGroupByID(groupWrapper.Model().ID)
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// GetRules
//
//	@Summary		Получить список правил
//	@Description	Возвращает список правил
//	@Tags			rules
//	@Produce		json
//	@Param			groupID	path		string	true	"ID группы"
//	@Success		200		{object}	types.RulesRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules [get]
func (h *Handler) GetRules(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	rules := h.userGroups()[groupIdx].Model().Rules
	utils.WriteJson(w, http.StatusOK, RespFromRules(rules))
}

// PutRules
//
//	@Summary		Обновить список правил
//	@Description	Обновляет список правил
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.RulesReq	true	"Тело запроса"
//	@Success		200		{object}	types.RulesRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules [put]
func (h *Handler) PutRules(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.RulesReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Rules == nil {
		utils.WriteError(w, http.StatusBadRequest, "no rules in request")
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.userGroups()[groupIdx]
	enabled := groupWrapper.Enabled()

	newRules := make([]*models.Rule, len(*req.Rules))
	for i, rr := range *req.Rules {
		id := intID.RandomID()
		if rr.ID != nil {
			found := false
			for _, oldRule := range groupWrapper.Model().Rules {
				if oldRule.ID == *rr.ID {
					id = *rr.ID
					found = true
					break
				}
			}
			if !found {
				utils.WriteError(w, http.StatusNotFound, "rule not found")
				return
			}
		}
		newRules[i] = &models.Rule{
			ID:     id,
			Name:   rr.Name,
			Type:   rr.Type,
			Rule:   rr.Rule,
			Enable: rr.Enable,
		}
	}
	groupWrapper.Model().Rules = newRules
	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	utils.WriteJson(w, http.StatusOK, RespFromRules(newRules))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// CreateRule
//
//	@Summary		Создать правило
//	@Description	Создает правило
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.RuleReq	true	"Тело запроса"
//	@Success		200		{object}	types.RuleRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules [post]
func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.RuleReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.userGroups()[groupIdx]
	enabled := groupWrapper.Enabled()

	rule, err := RuleFromReq(req, groupWrapper.Model().Rules)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupWrapper.Model().Rules = append(groupWrapper.Model().Rules, rule)
	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	utils.WriteJson(w, http.StatusOK, RespFromRule(rule))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// GetRule
//
//	@Summary		Получить правило
//	@Description	Возвращает запрошенное правило
//	@Tags			rules
//	@Produce		json
//	@Param			groupID	path		string	true	"ID группы"
//	@Param			ruleID	path		string	true	"ID правила"
//	@Success		200		{object}	types.RuleRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules/{ruleID} [get]
func (h *Handler) GetRule(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	rule := h.userGroups()[groupIdx].Model().Rules[ruleIdx]
	utils.WriteJson(w, http.StatusOK, RespFromRule(rule))
}

// PutRule
//
//	@Summary		Обновить правило
//	@Description	Обновляет запрошенное правило
//	@Tags			rules
//	@Accept			json
//	@Produce		json
//	@Param			groupID	path		string			true	"ID группы"
//	@Param			ruleID	path		string			true	"ID правила"
//	@Param			save	query		bool			false	"Сохранить изменения в конфигурационный файл"
//	@Param			json	body		types.RuleReq	true	"Тело запроса"
//	@Success		200		{object}	types.RuleRes
//	@Failure		400		{object}	types.ErrorRes
//	@Failure		404		{object}	types.ErrorRes
//	@Failure		500		{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules/{ruleID} [put]
func (h *Handler) PutRule(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.RuleReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.userGroups()[groupIdx]
	enabled := groupWrapper.Enabled()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	rule := groupWrapper.Model().Rules[ruleIdx]
	rule.Name = req.Name
	rule.Type = req.Type
	rule.Rule = req.Rule
	rule.Enable = req.Enable

	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	utils.WriteJson(w, http.StatusOK, RespFromRule(rule))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// DeleteRule
//
//	@Summary		Удалить правило
//	@Description	Удаляет запрошенное правило
//	@Tags			rules
//	@Produce		json
//	@Param			groupID	path	string	true	"ID группы"
//	@Param			ruleID	path	string	true	"ID правила"
//	@Param			save	query	bool	false	"Сохранить изменения в конфигурационный файл"
//	@Success		200
//	@Failure		404	{object}	types.ErrorRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/groups/{groupID}/rules/{ruleID} [delete]
func (h *Handler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.userGroups()[groupIdx]
	enabled := groupWrapper.Enabled()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	groupWrapper.Model().Rules = append(groupWrapper.Model().Rules[:ruleIdx], groupWrapper.Model().Rules[ruleIdx+1:]...)
	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			utils.WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

// GetVersion
//
//	@Summary		Получить версию MagiTrickle
//	@Description	Возвращает версию запущенного бинарника (constant.Version из ldflags); контроллеры используют как capability-флаг
//	@Tags			config
//	@Produce		json
//	@Success		200	{object}	types.VersionRes
//	@Router			/api/v1/version [get]
func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	utils.WriteJson(w, http.StatusOK, types.VersionRes{Version: constant.Version})
}

// GetDnsUpstreams
//
//	@Summary		Состояние каскада апстримов dns-proxy
//	@Description	Снимок стейта менеджера мультиапстрима (alive/active/счётчики/причина) + политика зондов; читается контроллером mawg
//	@Tags			dns
//	@Produce		json
//	@Success		200	{object}	types.DnsUpstreamsRes
//	@Router			/api/v1/dns/upstreams [get]
func (h *Handler) GetDnsUpstreams(w http.ResponseWriter, r *http.Request) {
	snap, ok := h.app.DnsUpstreamsSnapshot()
	if !ok {
		utils.WriteJson(w, http.StatusOK, types.DnsUpstreamsRes{
			Available: false,
			Upstreams: []types.DnsUpstreamState{},
		})
		return
	}
	res := types.DnsUpstreamsRes{
		Available: true,
		Health: types.DnsHealthRes{
			Enabled:       snap.Health.Enabled,
			Interval:      snap.Health.Interval.String(),
			Timeout:       snap.Health.Timeout.String(),
			FailCycles:    snap.Health.FailCycles,
			RestoreCycles: snap.Health.RestoreCycles,
			RestoreGap:    snap.Health.RestoreGap.String(),
		},
		Upstreams: make([]types.DnsUpstreamState, 0, len(snap.Upstreams)),
	}
	for _, u := range snap.Upstreams {
		res.Upstreams = append(res.Upstreams, types.DnsUpstreamState{
			Address:  u.Address,
			Alive:    u.Alive,
			Active:   u.Active,
			Fails:    u.Fails,
			Oks:      u.Oks,
			LastSwap: u.LastSwap,
			Reason:   u.Reason,
		})
	}
	utils.WriteJson(w, http.StatusOK, res)
}

// PutDnsUpstreams
//
//	@Summary		Замена списка апстримов dns-proxy
//	@Description	Порядок = приоритет; plain host:port (порт по умолчанию 53), DoT tls://host[:853], DoH https://host[:443][/dns-query]; сохраняет конфиг и горячо подменяет список без рестарта демона. С rev14: upstreams отсутствует = не трогать (запись только health - политики зондов: nil-поля = не трогать, длительности в секундах)
//	@Tags			dns
//	@Accept			json
//	@Produce		json
//	@Param			json	body	types.DnsUpstreamsPutReq	true	"Новый список апстримов"
//	@Success		200	{object}	types.DnsUpstreamsRes
//	@Failure		400	{object}	types.ErrorRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/dns/upstreams [put]
func (h *Handler) PutDnsUpstreams(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.DnsUpstreamsPutReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	var health *models.AppConfigDNSProxyHealthPatch
	if req.Health != nil {
		health = &models.AppConfigDNSProxyHealthPatch{
			Enabled:       req.Health.Enabled,
			IntervalSec:   req.Health.IntervalSec,
			TimeoutSec:    req.Health.TimeoutSec,
			FailCycles:    req.Health.FailCycles,
			RestoreCycles: req.Health.RestoreCycles,
			RestoreGapSec: req.Health.RestoreGapSec,
		}
	}
	if err := h.app.SetDnsUpstreams(req.Upstreams, health); err != nil {
		if errors.Is(err, app.ErrDnsUpstreamsInvalid) {
			utils.WriteError(w, http.StatusBadRequest, err.Error())
		} else {
			log.Error().Err(err).Msg("failed to set dns upstreams")
			utils.WriteError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	h.GetDnsUpstreams(w, r)
}

// GetDnsZones
//
//	@Summary		Состояние зонного DNS
//	@Description	Таблица зон со стейтом апстримов каждой (rev13); читается контроллером mawg
//	@Tags			dns
//	@Produce		json
//	@Success		200	{object}	types.DnsZonesRes
//	@Router			/api/v1/dns/zones [get]
func (h *Handler) GetDnsZones(w http.ResponseWriter, r *http.Request) {
	snaps, ok := h.app.DnsZonesSnapshot()
	if !ok {
		utils.WriteJson(w, http.StatusOK, types.DnsZonesRes{
			Available: false,
			Zones:     []types.DnsZoneRes{},
		})
		return
	}
	res := types.DnsZonesRes{
		Available: true,
		Zones:     make([]types.DnsZoneRes, 0, len(snaps)),
	}
	for _, s := range snaps {
		zr := types.DnsZoneRes{
			Zone:      s.Zone,
			Fallback:  s.FallbackOpen,
			Upstreams: make([]types.DnsUpstreamState, 0, len(s.Upstreams.Upstreams)),
		}
		for _, u := range s.Upstreams.Upstreams {
			zr.Upstreams = append(zr.Upstreams, types.DnsUpstreamState{
				Address:  u.Address,
				Alive:    u.Alive,
				Active:   u.Active,
				Fails:    u.Fails,
				Oks:      u.Oks,
				LastSwap: u.LastSwap,
				Reason:   u.Reason,
			})
		}
		res.Zones = append(res.Zones, zr)
	}
	utils.WriteJson(w, http.StatusOK, res)
}

// PutDnsZones
//
//	@Summary		Замена таблицы зон dns-proxy
//	@Description	Порядок апстримов зоны = приоритет; без Fallback - fail-closed (SERVFAIL при полном отвале зоны); сохраняет конфиг и горячо подменяет таблицу без рестарта демона; пустой список = очистка
//	@Tags			dns
//	@Accept			json
//	@Produce		json
//	@Param			json	body	types.DnsZonesPutReq	true	"Новая таблица зон"
//	@Success		200	{object}	types.DnsZonesRes
//	@Failure		400	{object}	types.ErrorRes
//	@Failure		500	{object}	types.ErrorRes
//	@Router			/api/v1/dns/zones [put]
func (h *Handler) PutDnsZones(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.DnsZonesPutReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	zones := make([]models.AppConfigDNSProxyZone, 0, len(req.Zones))
	for _, z := range req.Zones {
		zm := models.AppConfigDNSProxyZone{Zone: z.Zone, FallbackOpen: z.Fallback}
		zm.Upstreams = make([]models.AppConfigDNSProxyServer, 0, len(z.Upstreams))
		for _, a := range z.Upstreams {
			zm.Upstreams = append(zm.Upstreams, models.AppConfigDNSProxyServer{Address: a})
		}
		zones = append(zones, zm)
	}
	if err := h.app.SetDnsZones(zones); err != nil {
		if errors.Is(err, app.ErrDnsZonesInvalid) {
			utils.WriteError(w, http.StatusBadRequest, err.Error())
		} else {
			log.Error().Err(err).Msg("failed to set dns zones")
			utils.WriteError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	h.GetDnsZones(w, r)
}
