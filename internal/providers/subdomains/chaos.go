package subdomains

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
)

type ChaosProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
	apiKey      string
}

func NewChaosProvider(client *http.Client, cfg config.Settings) *ChaosProvider {
	rate := cfg.ProviderRateLimit["chaos"].RequestsPerSecond
	return &ChaosProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
		apiKey:      strings.TrimSpace(cfg.ChaosAPIKey),
	}
}

func (p *ChaosProvider) Name() string { return "chaos" }

func (p *ChaosProvider) CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error) {
	if p.apiKey == "" {
		return nil, errors.New("missing chaos api key")
	}
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://dns.projectdiscovery.io/dns/%s/subdomains", rootDomain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", p.apiKey)
	req.Header.Set("Accept", "application/json")

	body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
	if err != nil {
		return nil, err
	}
	return parseChaosJSON(body, rootDomain)
}

func parseChaosJSON(body []byte, rootDomain string) ([]string, error) {
	var resp struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(resp.Subdomains))
	for _, sub := range resp.Subdomains {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}
		if strings.Contains(sub, ".") {
			out = append(out, strings.ToLower(sub))
		} else {
			out = append(out, strings.ToLower(sub+"."+rootDomain))
		}
	}
	return out, nil
}
