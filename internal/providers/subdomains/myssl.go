package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
	"subdomain-tools/internal/providers"
)

type MySSLProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
}

func NewMySSLProvider(client *http.Client, cfg config.Settings) *MySSLProvider {
	rate := cfg.ProviderRateLimit["myssl"].RequestsPerSecond
	return &MySSLProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
	}
}

func (p *MySSLProvider) Name() string { return "myssl" }

func (p *MySSLProvider) CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error) {
	records, err := p.CollectSubdomainRecords(ctx, rootDomain)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Host)
	}
	return out, nil
}

func (p *MySSLProvider) CollectSubdomainRecords(ctx context.Context, rootDomain string) ([]providers.SubdomainRecord, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	domain := url.QueryEscape(strings.TrimSpace(rootDomain))
	endpoint := fmt.Sprintf("https://myssl.com/api/v1/discover_sub_domain?domain=%s", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
	if err != nil {
		return nil, err
	}
	return parseMySSLJSONRecords(body, rootDomain)
}

func parseMySSLJSON(body []byte, rootDomain string) ([]string, error) {
	records, err := parseMySSLJSONRecords(body, rootDomain)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Host)
	}
	return out, nil
}

func parseMySSLJSONRecords(body []byte, rootDomain string) ([]providers.SubdomainRecord, error) {
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			Domain string `json:"domain"`
			IP     string `json:"ip"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("api code: %d", resp.Code)
	}

	root := strings.ToLower(strings.TrimSpace(rootDomain))
	out := make([]providers.SubdomainRecord, 0, len(resp.Data))
	for _, item := range resp.Data {
		host := normalizeHost(item.Domain)
		if host == "" {
			continue
		}
		if host == root || strings.HasSuffix(host, "."+root) {
			ip := strings.TrimSpace(item.IP)
			if _, err := netip.ParseAddr(ip); err != nil {
				ip = ""
			}
			out = append(out, providers.SubdomainRecord{Host: host, IP: ip})
		}
	}
	return out, nil
}
