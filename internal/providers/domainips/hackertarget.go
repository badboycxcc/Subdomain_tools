package domainips

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
)

type HostIPProvider interface {
	Name() string
	CollectHostIPs(ctx context.Context, rootDomain string) (map[string][]string, error)
}

type HackerTargetHostSearchProvider struct {
	client *http.Client
	retry  int
	rate   *netx.RateLimiter
}

func NewHackerTargetHostSearchProvider(client *http.Client, cfg config.Settings) *HackerTargetHostSearchProvider {
	return &HackerTargetHostSearchProvider{
		client: client,
		retry:  cfg.MaxRetries,
		rate:   netx.NewRateLimiter(1),
	}
}

func (p *HackerTargetHostSearchProvider) Name() string { return "hackertarget_hostsearch" }

func (p *HackerTargetHostSearchProvider) CollectHostIPs(ctx context.Context, rootDomain string) (map[string][]string, error) {
	if err := p.rate.Wait(ctx); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", rootDomain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	body, err := netx.DoRequestWithRetry(ctx, p.client, req, p.retry)
	if err != nil {
		return nil, err
	}
	return parseHostSearch(body), nil
}

func parseHostSearch(body []byte) map[string][]string {
	out := map[string][]string{}
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
		host := strings.ToLower(strings.TrimSpace(parts[0]))
		ip := strings.TrimSpace(parts[1])
		if host == "" || ip == "" {
			continue
		}
		if !contains(out[host], ip) {
			out[host] = append(out[host], ip)
		}
	}
	return out
}

func contains(list []string, value string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}
	return false
}
