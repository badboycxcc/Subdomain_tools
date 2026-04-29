package reverseip

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
	"subdomain-tools/internal/providers/subdomains"
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

func (p *URLScanProvider) CollectDomainsByIP(ctx context.Context, ip string) ([]string, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	q := url.QueryEscape("ip:" + strings.TrimSpace(ip))
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
	return parseURLScanReverseIPJSON(body)
}

func parseURLScanReverseIPJSON(body []byte) ([]string, error) {
	var resp struct {
		Results []struct {
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(resp.Results)*2)
	seen := map[string]struct{}{}
	for _, item := range resp.Results {
		for _, raw := range []string{item.Task.Domain, item.Page.Domain} {
			host := subdomains.NormalizeForReverseIP(raw)
			if host == "" {
				continue
			}
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			out = append(out, host)
		}
	}
	return out, nil
}
