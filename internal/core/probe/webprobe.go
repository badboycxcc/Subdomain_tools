package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type Result struct {
	TargetURL     string
	Host          string
	ResolvedIP    string
	StatusCode    int
	Title         string
	Server        string
	ContentType   string
	Technologies  []string
	ResponseBytes int
	Error         string
}

type Prober struct {
	client   *http.Client
	detector *wappalyzer.Wappalyze
}

func NewProber(timeout time.Duration) (*Prober, error) {
	d, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	return &Prober{
		client:   client,
		detector: d,
	}, nil
}

func (p *Prober) ProbeURL(ctx context.Context, rawURL string) Result {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{TargetURL: rawURL, Error: err.Error()}
	}
	return p.do(req, "")
}

func (p *Prober) ProbeHostCollision(
	ctx context.Context,
	scheme string,
	host string,
	ip string,
) Result {
	target := fmt.Sprintf("%s://%s", scheme, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Result{TargetURL: target, Host: host, ResolvedIP: ip, Error: err.Error()}
	}
	req.Host = host
	result := p.do(req, ip)
	result.Host = host
	result.ResolvedIP = ip
	return result
}

func (p *Prober) ProbeHostAuto(ctx context.Context, host string) Result {
	for _, scheme := range []string{"https", "http"} {
		target := fmt.Sprintf("%s://%s", scheme, host)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return Result{TargetURL: target, Host: host, Error: err.Error()}
		}
		result := p.do(req, "")
		result.Host = host
		if result.Error == "" {
			return result
		}
	}
	return Result{Host: host, Error: "both https/http probe failed"}
}

func (p *Prober) do(req *http.Request, resolvedIP string) Result {
	resp, err := p.client.Do(req)
	if err != nil {
		return Result{
			TargetURL:  req.URL.String(),
			Host:       req.Host,
			ResolvedIP: resolvedIP,
			Error:      err.Error(),
		}
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if readErr != nil {
		return Result{
			TargetURL:  req.URL.String(),
			Host:       req.Host,
			ResolvedIP: resolvedIP,
			StatusCode: resp.StatusCode,
			Error:      readErr.Error(),
		}
	}

	fingerprints := p.detector.Fingerprint(resp.Header, body)
	tech := make([]string, 0, len(fingerprints))
	for k := range fingerprints {
		tech = append(tech, k)
	}
	sort.Strings(tech)

	host := req.URL.Hostname()
	if req.Host != "" {
		host = req.Host
	}

	return Result{
		TargetURL:     req.URL.String(),
		Host:          host,
		ResolvedIP:    resolvedIP,
		StatusCode:    resp.StatusCode,
		Title:         extractHTMLTitle(body),
		Server:        resp.Header.Get("Server"),
		ContentType:   resp.Header.Get("Content-Type"),
		Technologies:  tech,
		ResponseBytes: len(body),
	}
}

func BuildURLsForHost(host string) []string {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return []string{host}
	}
	return []string{"https://" + host, "http://" + host}
}

func NormalizeHost(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return ""
	}
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if u, err := url.Parse(input); err == nil {
			input = u.Hostname()
		}
	}
	input = strings.TrimSuffix(input, ".")
	return input
}

func ResolveCurrentIPs(ctx context.Context, host string) ([]string, error) {
	host = NormalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		ip := a.IP.String()
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	sort.Strings(out)
	return out, nil
}

var titleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractHTMLTitle(body []byte) string {
	m := titleRegex.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	title := strings.TrimSpace(string(m[1]))
	title = strings.Join(strings.Fields(title), " ")
	return title
}
