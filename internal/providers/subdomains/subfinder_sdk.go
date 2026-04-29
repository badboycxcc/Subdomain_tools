package subdomains

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"

	"subdomain-tools/internal/config"
)

type SubfinderSDKProvider struct {
	timeoutSec int
	maxMin     int
}

func NewSubfinderSDKProvider(cfg config.Settings) *SubfinderSDKProvider {
	timeout := cfg.HTTPTimeoutSecond
	if timeout <= 0 {
		timeout = 20
	}
	return &SubfinderSDKProvider{
		timeoutSec: timeout,
		maxMin:     5,
	}
}

func (p *SubfinderSDKProvider) Name() string { return "subfinder_sdk" }

func (p *SubfinderSDKProvider) CollectSubdomains(ctx context.Context, rootDomain string) ([]string, error) {
	rootDomain = strings.ToLower(strings.TrimSpace(rootDomain))
	opts := &runner.Options{
		Silent:             true,
		NoColor:            true,
		DisableUpdateCheck: true,
		Timeout:            p.timeoutSec,
		MaxEnumerationTime: p.maxMin,
	}

	seen := map[string]struct{}{}
	out := make([]string, 0, 128)
	var mu sync.Mutex
	opts.ResultCallback = func(result *resolve.HostEntry) {
		if result == nil {
			return
		}
		host := strings.ToLower(strings.TrimSpace(result.Host))
		if host == "" {
			return
		}
		if host != rootDomain && !strings.HasSuffix(host, "."+rootDomain) {
			return
		}
		mu.Lock()
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			out = append(out, host)
		}
		mu.Unlock()
	}

	r, err := runner.NewRunner(opts)
	if err != nil {
		return nil, err
	}

	if _, err = r.EnumerateSingleDomainWithCtx(ctx, rootDomain, nil); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}
