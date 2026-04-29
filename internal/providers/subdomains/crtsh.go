package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
)

type CrtshProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
}

func NewCrtshProvider(client *http.Client, cfg config.Settings) *CrtshProvider {
	rate := cfg.ProviderRateLimit["crtsh"].RequestsPerSecond
	return &CrtshProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
	}
}

func (p *CrtshProvider) Name() string { return "crtsh" }

func (p *CrtshProvider) CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	q := url.QueryEscape("%." + rootDomain)
	endpoint := fmt.Sprintf("https://crt.sh/?q=%s&output=json", q)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
	if err != nil {
		return nil, err
	}
	return parseCRTShJSON(body, rootDomain)
}

func parseCRTShJSON(body []byte, rootDomain string) ([]string, error) {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(rows))
	for _, row := range rows {
		for _, item := range strings.Split(row.NameValue, "\n") {
			host := normalizeHost(item)
			if host == "" || !strings.HasSuffix(host, "."+strings.ToLower(rootDomain)) && host != strings.ToLower(rootDomain) {
				continue
			}
			out = append(out, host)
		}
	}
	return out, nil
}

func normalizeHost(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if strings.ContainsAny(s, " \t/") {
		return ""
	}
	return s
}
