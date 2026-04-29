package subdomains

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
)

type IPTHCSubdomainProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
}

func NewIPTHCSubdomainProvider(client *http.Client, cfg config.Settings) *IPTHCSubdomainProvider {
	rate := cfg.ProviderRateLimit["ipthc_subdomain"].RequestsPerSecond
	return &IPTHCSubdomainProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
	}
}

func (p *IPTHCSubdomainProvider) Name() string { return "ipthc_subdomain" }

func (p *IPTHCSubdomainProvider) CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]string{"domain": rootDomain})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://ip.thc.org/api/v1/lookup/subdomains", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
	if err != nil {
		return nil, err
	}
	return parseIPTHCSubdomainJSON(body, rootDomain)
}

func parseIPTHCSubdomainJSON(body []byte, rootDomain string) ([]string, error) {
	var resp struct {
		Domains []struct {
			Domain string `json:"domain"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	root := strings.ToLower(strings.TrimSpace(rootDomain))
	out := make([]string, 0, len(resp.Domains))
	for _, d := range resp.Domains {
		host := normalizeHost(d.Domain)
		if host == "" {
			continue
		}
		if host == root || strings.HasSuffix(host, "."+root) {
			out = append(out, host)
		}
	}
	return out, nil
}
