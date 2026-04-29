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

type RapidDNSProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
	apiKey      string
}

func NewRapidDNSProvider(client *http.Client, cfg config.Settings) *RapidDNSProvider {
	rate := cfg.ProviderRateLimit["rapiddns"].RequestsPerSecond
	return &RapidDNSProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
		apiKey:      strings.TrimSpace(cfg.RapidDNSAPIKey),
	}
}

func (p *RapidDNSProvider) Name() string { return "rapiddns" }

func (p *RapidDNSProvider) CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error) {
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

func (p *RapidDNSProvider) CollectSubdomainRecords(ctx context.Context, rootDomain string) ([]providers.SubdomainRecord, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("rapiddns api key 未配置")
	}
	root := strings.TrimSpace(rootDomain)
	if root == "" {
		return nil, fmt.Errorf("empty root domain")
	}

	page := 1
	pageSize := 100
	total := -1
	out := make([]providers.SubdomainRecord, 0, 256)
	for page <= 20 {
		if err := p.rateLimiter.Wait(ctx); err != nil {
			return nil, err
		}

		endpoint := fmt.Sprintf(
			"https://rapiddns.io/api/search/%s?page=%d&pagesize=%d&search_type=subdomain",
			url.PathEscape(root), page, pageSize,
		)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-API-KEY", p.apiKey)

		body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
		if err != nil {
			return nil, err
		}

		records, pageTotal, err := parseRapidDNSJSONRecords(body, root)
		if err != nil {
			return nil, err
		}
		out = append(out, records...)
		if total < 0 {
			total = pageTotal
		}
		if len(records) < pageSize || (total >= 0 && len(out) >= total) {
			break
		}
		page++
	}
	return out, nil
}

func parseRapidDNSJSON(body []byte, rootDomain string) ([]string, int, error) {
	records, total, err := parseRapidDNSJSONRecords(body, rootDomain)
	if err != nil {
		return nil, 0, err
	}
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Host)
	}
	return out, total, nil
}

func parseRapidDNSJSONRecords(body []byte, rootDomain string) ([]providers.SubdomainRecord, int, error) {
	var resp struct {
		Data struct {
			Total json.RawMessage `json:"total"`
			Data  []struct {
				Subdomain string `json:"subdomain"`
				Value     string `json:"value"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, err
	}

	total := parseRapidDNSTotal(resp.Data.Total)
	root := strings.ToLower(strings.TrimSpace(rootDomain))
	out := make([]providers.SubdomainRecord, 0, len(resp.Data.Data))
	for _, item := range resp.Data.Data {
		host := normalizeHost(item.Subdomain)
		if host == "" {
			continue
		}
		if host == root || strings.HasSuffix(host, "."+root) {
			ip := strings.TrimSpace(item.Value)
			if _, err := netip.ParseAddr(ip); err != nil {
				ip = ""
			}
			out = append(out, providers.SubdomainRecord{Host: host, IP: ip})
		}
	}
	return out, total, nil
}

func parseRapidDNSTotal(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		v, err := strconv.Atoi(s)
		if err == nil {
			return v
		}
	}
	return 0
}
