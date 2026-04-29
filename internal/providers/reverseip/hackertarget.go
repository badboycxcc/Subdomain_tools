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

type HackerTargetProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
}

func NewHackerTargetProvider(client *http.Client, cfg config.Settings) *HackerTargetProvider {
	rate := cfg.ProviderRateLimit["hackertarget"].RequestsPerSecond
	return &HackerTargetProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
	}
}

func (p *HackerTargetProvider) Name() string { return "hackertarget" }

func (p *HackerTargetProvider) CollectDomainsByIP(ctx context.Context, ip string) ([]string, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
	if err != nil {
		return nil, err
	}
	return parseHackerTargetLines(body)
}

func parseHackerTargetLines(body []byte) ([]string, error) {
	out := make([]string, 0, 64)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "error check your search parameter") {
			return nil, fmt.Errorf("hackertarget response: %s", line)
		}
		host := strings.TrimSpace(strings.Split(line, ",")[0])
		host = subdomains.NormalizeForReverseIP(host)
		if host != "" {
			out = append(out, host)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
