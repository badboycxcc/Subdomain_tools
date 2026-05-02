package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
	"subdomain-tools/internal/providers"
)

type ViewDNSProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
	apiKey      string
}

func NewViewDNSProvider(client *http.Client, cfg config.Settings) *ViewDNSProvider {
	rate := cfg.ProviderRateLimit["viewdns"].RequestsPerSecond
	return &ViewDNSProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
		apiKey:      strings.TrimSpace(cfg.ViewDNSAPIKey),
	}
}

func (p *ViewDNSProvider) Name() string { return "viewdns" }

func (p *ViewDNSProvider) CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error) {
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

func (p *ViewDNSProvider) CollectSubdomainRecords(ctx context.Context, rootDomain string) ([]providers.SubdomainRecord, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("viewdns api key 未配置")
	}
	root := strings.TrimSpace(rootDomain)
	if root == "" {
		return nil, fmt.Errorf("empty root domain")
	}

	page := 1
	totalPages := -1
	out := make([]providers.SubdomainRecord, 0, 256)
	for page <= 20 {
		if err := p.rateLimiter.Wait(ctx); err != nil {
			return nil, err
		}
		endpoint := fmt.Sprintf(
			"https://api.viewdns.info/subdomains/?domain=%s&apikey=%s&page=%d&output=json",
			url.QueryEscape(root),
			url.QueryEscape(p.apiKey),
			page,
		)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
		if err != nil {
			return nil, err
		}
		records, pages, err := parseViewDNSSubdomainsJSONRecords(body, root)
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
		if totalPages < 0 {
			totalPages = pages
		}
		if len(records) == 0 || (totalPages > 0 && page >= totalPages) {
			break
		}
		page++
	}
	return out, nil
}

func parseViewDNSSubdomainsJSONRecords(body []byte, rootDomain string) ([]providers.SubdomainRecord, int, error) {
	var resp struct {
		Response *struct {
			TotalPages string `json:"total_pages"`
			Subdomains []struct {
				Name string   `json:"name"`
				IPs  []string `json:"ips"`
			} `json:"subdomains"`
		} `json:"response"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, err
	}
	if strings.TrimSpace(resp.Error) != "" {
		return nil, 0, fmt.Errorf("viewdns response: %s", strings.TrimSpace(resp.Error))
	}
	if resp.Response == nil {
		return nil, 0, nil
	}

	totalPages := 0
	if v := strings.TrimSpace(resp.Response.TotalPages); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			totalPages = n
		}
	}

	root := strings.ToLower(strings.TrimSpace(rootDomain))
	out := make([]providers.SubdomainRecord, 0, len(resp.Response.Subdomains))
	for _, item := range resp.Response.Subdomains {
		host := normalizeHost(item.Name)
		if host == "" {
			continue
		}
		if host != root && !strings.HasSuffix(host, "."+root) {
			continue
		}
		ip := ""
		for _, candidate := range item.IPs {
			candidate = strings.TrimSpace(candidate)
			if _, err := netip.ParseAddr(candidate); err == nil {
				ip = candidate
				break
			}
		}
		out = append(out, providers.SubdomainRecord{Host: host, IP: ip})
	}
	return out, totalPages, nil
}
