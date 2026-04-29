package probe

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var defaultDNSResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"223.5.5.5:53",
}

// ResolveARecordsWithDNSX resolves A records for hosts with built-in dnsx-like logic.
// It does not depend on local dnsx executable.
func ResolveARecordsWithDNSX(ctx context.Context, hosts []string, resolvers []string) (map[string][]string, error) {
	inputHosts := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = NormalizeHost(h)
		if h == "" {
			continue
		}
		inputHosts = append(inputHosts, h)
	}
	if len(inputHosts) == 0 {
		return map[string][]string{}, nil
	}
	resolverList := normalizeResolvers(resolvers)

	result := map[string][]string{}
	workerN := 64
	if len(inputHosts) < workerN {
		workerN = len(inputHosts)
	}
	jobs := make(chan string, len(inputHosts))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errCnt int

	for i := 0; i < workerN; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				ips, err := resolveAWithRetry(ctx, host, resolverList, 2, 3*time.Second)
				if err != nil {
					mu.Lock()
					errCnt++
					mu.Unlock()
					continue
				}
				if len(ips) == 0 {
					continue
				}
				mu.Lock()
				result[host] = ips
				mu.Unlock()
			}
		}()
	}

	for _, h := range inputHosts {
		jobs <- h
	}
	close(jobs)
	wg.Wait()

	if len(result) == 0 && errCnt > 0 {
		return nil, fmt.Errorf("dns a 解析失败，全部查询未命中")
	}
	return result, nil
}

func resolveAWithRetry(ctx context.Context, host string, resolvers []string, retries int, timeout time.Duration) ([]string, error) {
	if retries < 1 {
		retries = 1
	}
	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		ips, err := resolveAOnce(ctx, host, shuffledResolvers(resolvers), timeout)
		if err == nil {
			return ips, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func resolveAOnce(ctx context.Context, host string, resolvers []string, timeout time.Duration) ([]string, error) {
	host = NormalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
	msg.RecursionDesired = true

	var lastErr error
	for _, resolver := range resolvers {
		c := &dns.Client{Net: "udp", Timeout: timeout}
		resp, _, err := c.ExchangeContext(ctx, msg, ensureDNSPort(resolver))
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil || resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("rcode=%d", resp.Rcode)
			continue
		}
		ips := make([]string, 0, len(resp.Answer))
		seen := make(map[string]struct{}, len(resp.Answer))
		for _, ans := range resp.Answer {
			rec, ok := ans.(*dns.A)
			if !ok {
				continue
			}
			ip := rec.A.String()
			if net.ParseIP(ip) == nil {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		return ips, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no resolver response")
	}
	return nil, lastErr
}

func ensureDNSPort(resolver string) string {
	r := strings.TrimSpace(resolver)
	if r == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(r); err == nil {
		return r
	}
	return net.JoinHostPort(r, "53")
}

func shuffledResolvers(in []string) []string {
	out := append([]string(nil), in...)
	// Light shuffle to spread resolver load.
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func normalizeResolvers(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		p := ensureDNSPort(r)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return append([]string(nil), defaultDNSResolvers...)
	}
	return out
}
