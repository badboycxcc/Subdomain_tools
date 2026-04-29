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

type URLScanProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
}

func NewURLScanProvider(client *http.Client, cfg config.Settings) *URLScanProvider {
	rate := cfg.ProviderRateLimit["urlscan"].RequestsPerSecond
	return &URLScanProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
	}
}

func (p *URLScanProvider) Name() string { return "urlscan" }

func (p *URLScanProvider) CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error) {
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

func (p *URLScanProvider) CollectSubdomainRecords(ctx context.Context, rootDomain string) ([]providers.SubdomainRecord, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	q := url.QueryEscape("domain:" + strings.TrimSpace(rootDomain))
	endpoint := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=%s", q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
	if err != nil {
		return nil, err
	}
	return parseURLScanJSONRecords(body, rootDomain)
}

func parseURLScanJSON(body []byte, rootDomain string) ([]string, error) {
	records, err := parseURLScanJSONRecords(body, rootDomain)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Host)
	}
	return out, nil
}

func parseURLScanJSONRecords(body []byte, rootDomain string) ([]providers.SubdomainRecord, error) {
	var resp struct {
		Results []struct {
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
			Page struct {
				Domain string `json:"domain"`
				IP     string `json:"ip"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	root := strings.ToLower(strings.TrimSpace(rootDomain))
	out := make([]providers.SubdomainRecord, 0, len(resp.Results))
	for _, item := range resp.Results {
		ip := strings.TrimSpace(item.Page.IP)
		if _, err := netip.ParseAddr(ip); err != nil {
			ip = ""
		}
		for _, candidate := range []string{item.Task.Domain, item.Page.Domain} {
			host := normalizeHost(candidate)
			if host == "" {
				continue
			}
			if host == root || strings.HasSuffix(host, "."+root) {
				out = append(out, providers.SubdomainRecord{Host: host, IP: ip})
			}
		}
	}
	return out, nil
}
