package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
	"subdomain-tools/internal/providers"
)

type HackerTargetHostSearchSubdomainProvider struct {
	client      *http.Client
	retry       int
	rateLimiter *netx.RateLimiter
}

func NewHackerTargetHostSearchSubdomainProvider(client *http.Client, cfg config.Settings) *HackerTargetHostSearchSubdomainProvider {
	rate := cfg.ProviderRateLimit["hackertarget"].RequestsPerSecond
	return &HackerTargetHostSearchSubdomainProvider{
		client:      client,
		retry:       cfg.MaxRetries,
		rateLimiter: netx.NewRateLimiter(rate),
	}
}

func (p *HackerTargetHostSearchSubdomainProvider) Name() string {
	return "hackertarget_hostsearch_subdomain"
}

func (p *HackerTargetHostSearchSubdomainProvider) CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error) {
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

func (p *HackerTargetHostSearchSubdomainProvider) CollectSubdomainRecords(ctx context.Context, rootDomain string) ([]providers.SubdomainRecord, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", strings.TrimSpace(rootDomain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
	if err != nil {
		return nil, err
	}
	return parseHackerTargetHostSearchRecords(body, rootDomain), nil
}

func parseHackerTargetHostSearchLines(body []byte, rootDomain string) []string {
	rs := parseHackerTargetHostSearchRecords(body, rootDomain)
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Host)
	}
	return out
}

func parseHackerTargetHostSearchRecords(body []byte, rootDomain string) []providers.SubdomainRecord {
	root := strings.ToLower(strings.TrimSpace(rootDomain))
	out := make([]providers.SubdomainRecord, 0, 64)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(strings.ToLower(line), "error check your search parameter") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		host := normalizeHost(parts[0])
		if host == "" {
			continue
		}
		if host == root || strings.HasSuffix(host, "."+root) {
			ip := strings.TrimSpace(parts[1])
			if _, err := netip.ParseAddr(ip); err != nil {
				ip = ""
			}
			out = append(out, providers.SubdomainRecord{Host: host, IP: ip})
		}
	}
	return out
}
