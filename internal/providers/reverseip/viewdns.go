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

func (p *ViewDNSProvider) CollectDomainsByIP(ctx context.Context, ip string) ([]string, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("viewdns api key 未配置")
	}
	target := strings.TrimSpace(ip)
	if target == "" {
		return nil, fmt.Errorf("empty ip")
	}
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf(
		"https://api.viewdns.info/reverseip/?host=%s&apikey=%s&output=json",
		url.QueryEscape(target),
		url.QueryEscape(p.apiKey),
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
	return parseViewDNSReverseIPJSON(body)
}

func parseViewDNSReverseIPJSON(body []byte) ([]string, error) {
	var resp struct {
		Response *struct {
			Domains []struct {
				Name string `json:"name"`
			} `json:"domains"`
		} `json:"response"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if strings.TrimSpace(resp.Error) != "" {
		return nil, fmt.Errorf("viewdns response: %s", strings.TrimSpace(resp.Error))
	}
	if resp.Response == nil {
		return nil, nil
	}

	out := make([]string, 0, len(resp.Response.Domains))
	seen := map[string]struct{}{}
	for _, item := range resp.Response.Domains {
		host := subdomains.NormalizeForReverseIP(item.Name)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out, nil
}
