package providers

import (
	"context"
	"net/http"

	"subdomain-tools/internal/config"
)

type BaseProvider interface {
	Name() string
}

type SubdomainProvider interface {
	BaseProvider
	CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error)
}

type SubdomainRecord struct {
	Host string
	IP   string
}

type SubdomainRecordProvider interface {
	BaseProvider
	CollectSubdomainRecords(ctx context.Context, rootDomain string) ([]SubdomainRecord, error)
}

type ReverseIPProvider interface {
	BaseProvider
	CollectDomainsByIP(ctx context.Context, ip string) ([]string, error)
}

type ProviderDeps struct {
	Client   *http.Client
	Settings config.Settings
}
