package reverseip

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
	"subdomain-tools/internal/providers/subdomains"
)

type IPTHCProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
}

func NewIPTHCProvider(client *http.Client, cfg config.Settings) *IPTHCProvider {
	rate := cfg.ProviderRateLimit["ipthc"].RequestsPerSecond
	return &IPTHCProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
	}
}

func (p *IPTHCProvider) Name() string { return "ipthc" }

func (p *IPTHCProvider) CollectDomainsByIP(ctx context.Context, ip string) ([]string, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("https://ip.thc.org/%s?l=100&noheader=1", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
	if err != nil {
		// Fallback for old query style if route format changes.
		fallback := fmt.Sprintf("https://ip.thc.org/?ip=%s", ip)
		req2, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, fallback, nil)
		if reqErr != nil {
			return nil, err
		}
		body, err = netx.DoRequestWithRetry(ctx, p.client, req2, p.retry)
		if err != nil {
			return nil, err
		}
	}
	return parsePlainLines(body), nil
}

func parsePlainLines(body []byte) []string {
	out := make([]string, 0, 64)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		host := subdomainsNormalize(line)
		if host != "" {
			out = append(out, host)
		}
	}
	return out
}

func subdomainsNormalize(raw string) string {
	raw = strings.Fields(raw)[0]
	return subdomains.NormalizeForReverseIP(raw)
}
