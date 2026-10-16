package app

import (
	"context"
	"errors"
	"time"

	"magitrickle/models"
	"magitrickle/utils/dnsMITMProxy"
	"magitrickle/utils/intID"
	"magitrickle/utils/netfilterTools"

	"github.com/vishvananda/netlink"
)

var (
	ErrSubscriptionConflict = errors.New("subscription id conflict")
	ErrSubscriptionNotFound = errors.New("subscription not found")
	ErrSubscriptionInvalid  = errors.New("subscription invalid")
	ErrSubscriptionFetch    = errors.New("subscription fetch failed")
	ErrDnsUpstreamsInvalid  = errors.New("dns upstreams invalid")
)

type SubscriptionSyncResult struct {
	URL        string
	LastUpdate uint32
	Rules      []*models.SubscriptionRule
}

type Main interface {
	Config() models.AppConfig
	UserGroups() []RuleSet
	ClearGroups()
	AddGroup(groupModel *models.Group) error
	RemoveGroupByIndex(idx int)
	RemoveGroupByID(id intID.ID) bool
	SyncSubscriptionRuleSets() error
	WithSubscriptions(fn func([]*models.Subscription))
	ReplaceSubscriptions(subscriptions []*models.Subscription) error
	AddSubscription(subscription *models.Subscription) error
	RemoveSubscriptionByID(id intID.ID) (bool, error)
	SyncSubscriptionByID(id intID.ID, now time.Time, urlOverride string) (result SubscriptionSyncResult, changed bool, err error)
	SyncDueSubscriptions(now time.Time) (bool, error)
	ListInterfaces() ([]models.InterfaceInfo, error)
	DnsOverrider() *netfilterTools.PortRemap
	// DnsUpstreamsSnapshot - состояние апстримов dns-proxy (API rev8);
	// ok=false, если dns-proxy ещё не построен (до Start).
	DnsUpstreamsSnapshot() (snap dnsMITMProxy.UpstreamsSnapshot, ok bool)
	// SetDnsUpstreams - замена списка апстримов (host:port, порядок =
	// приоритет) с персистентной записью и горячей подменой живому
	// dns-proxy; ErrDnsUpstreamsInvalid - кривой/пустой список.
	SetDnsUpstreams(addrs []string) error
	LoadConfig() error
	SaveConfig() error
	ForceCommitIPTables() error
	Start(ctx context.Context) (err error)
}

type RuleSet interface {
	Enabled() bool
	Model() *models.Group
	AddIPv4Subnet(subnet netfilterTools.IPv4Subnet, ttl netfilterTools.IPSetTimeout) error
	AddIPv6Subnet(subnet netfilterTools.IPv6Subnet, ttl netfilterTools.IPSetTimeout) error
	DelIPv4Subnet(subnet netfilterTools.IPv4Subnet) error
	DelIPv6Subnet(subnet netfilterTools.IPv6Subnet) error
	ListIPv4Subnets() (map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout, error)
	ListIPv6Subnets() (map[netfilterTools.IPv6Subnet]netfilterTools.IPSetTimeout, error)
	Enable() error
	Disable() error
	Sync() error
	LinkUpHook(event netlink.LinkUpdate) error
	AddrChangeHook(event netlink.AddrUpdate) error
}
