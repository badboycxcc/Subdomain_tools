package reverseip

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/netx"
	"subdomain-tools/internal/providers/subdomains"
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

func (p *RapidDNSProvider) CollectDomainsByIP(ctx context.Context, ip string) ([]string, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("rapiddns api key 未配置")
	}
	target := strings.TrimSpace(ip)
	if target == "" {
		return nil, fmt.Errorf("empty ip")
	}

	page := 1
	pageSize := 100
	total := -1
	out := make([]string, 0, 256)
	seen := map[string]struct{}{}
	for page <= 20 {
		if err := p.rateLimiter.Wait(ctx); err != nil {
			return nil, err
		}

		endpoint := fmt.Sprintf(
			"https://rapiddns.io/api/search/%s?page=%d&pagesize=%d&search_type=ip",
			url.PathEscape(target), page, pageSize,
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
		hosts, pageTotal, err := parseRapidDNSReverseIPJSON(body)
		if err != nil {
			return nil, err
		}
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			out = append(out, host)
		}
		if total < 0 {
			total = pageTotal
		}
		if len(hosts) < pageSize || (total >= 0 && len(out) >= total) {
			break
		}
		page++
	}
	return out, nil
}

func parseRapidDNSReverseIPJSON(body []byte) ([]string, int, error) {
	var resp struct {
		Status int             `json:"status"`
		Msg    string          `json:"msg"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, err
	}
	if len(resp.Data) == 0 || string(resp.Data) == "null" {
		if strings.TrimSpace(resp.Msg) != "" {
			return nil, 0, fmt.Errorf("rapiddns response: %s", strings.TrimSpace(resp.Msg))
		}
		return nil, 0, nil
	}
	// RapidDNS 在错误场景可能返回 data 为字符串而非对象。
	if len(resp.Data) > 0 && resp.Data[0] == '"' {
		var dataMsg string
		if err := json.Unmarshal(resp.Data, &dataMsg); err == nil {
			msg := strings.TrimSpace(dataMsg)
			if msg == "" {
				msg = strings.TrimSpace(resp.Msg)
			}
			if msg != "" {
				return nil, 0, fmt.Errorf("rapiddns response: %s", msg)
			}
			return nil, 0, fmt.Errorf("rapiddns response data format invalid")
		}
	}

	var payload struct {
		Total json.RawMessage `json:"total"`
		Data  []struct {
			Subdomain string `json:"subdomain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Data, &payload); err != nil {
		return nil, 0, err
	}
	total := parseRapidDNSTotal(payload.Total)
	out := make([]string, 0, len(payload.Data))
	seen := map[string]struct{}{}
	for _, item := range payload.Data {
		host := subdomains.NormalizeForReverseIP(item.Subdomain)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
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
