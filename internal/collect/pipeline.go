package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"subdomain-tools/internal/core/model"
	"subdomain-tools/internal/core/probe"
	"subdomain-tools/internal/providers"
	"subdomain-tools/internal/providers/domainips"
)

func (o *Orchestrator) RunPipelineTask(
	ctx context.Context,
	rootDomain string,
	subProviders []providers.SubdomainProvider,
	hostIPProviders []domainips.HostIPProvider,
	prober *probe.Prober,
	dnsResolvers []string,
	enableHostsCollision bool,
) <-chan Event {
	events := make(chan Event, 512)
	go func() {
		defer close(events)
		o.runPipeline(ctx, rootDomain, subProviders, hostIPProviders, prober, dnsResolvers, enableHostsCollision, events)
	}()
	return events
}

func (o *Orchestrator) runPipeline(
	ctx context.Context,
	rootDomain string,
	subProviders []providers.SubdomainProvider,
	hostIPProviders []domainips.HostIPProvider,
	prober *probe.Prober,
	dnsResolvers []string,
	enableHostsCollision bool,
	events chan<- Event,
) {
	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Message:  fmt.Sprintf("开始全流程：目标域名 %s", rootDomain),
	}
	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Message:  "步骤1/4：收集子域名",
	}
	subdomains, sourceMap, apiIPsByHost := o.collectSubdomains(ctx, rootDomain, subProviders, events)
	apiAllIPs := flattenIPMap(apiIPsByHost)
	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Message:  fmt.Sprintf("%s 子域名收集完成，共 %d 个", rootDomain, len(subdomains)),
	}

	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Message:  "步骤2/4：归类 API 查询 IP + dnsx 解析 A 记录",
	}
	providerIPs := o.collectProviderAPIIPs(ctx, rootDomain, hostIPProviders, events)
	for host, ips := range providerIPs {
		apiIPsByHost[host] = mergeUniqueIPs(apiIPsByHost[host], ips)
	}
	apiAllIPs = flattenIPMap(apiIPsByHost)
	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Message:  fmt.Sprintf("API 查询 IP 归类完成：域名 %d 个，IP %d 个", len(apiIPsByHost), len(apiAllIPs)),
	}
	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Provider: "dnsx",
		Message:  fmt.Sprintf("dnsx A 记录查询开始：目标 %d 个，解析器 %v", len(subdomains), dnsResolvers),
	}

	dnsxIPsByHost, err := probe.ResolveARecordsWithDNSX(ctx, subdomains, dnsResolvers)
	if err != nil {
		events <- Event{
			Type:     EventLog,
			Time:     time.Now(),
			TaskType: model.TaskPipeline,
			Provider: "dnsx",
			Message:  fmt.Sprintf("dnsx A 记录查询失败: %v", err),
			Err:      err,
		}
		dnsxIPsByHost = map[string][]string{}
	}
	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Provider: "dnsx",
		Message:  fmt.Sprintf("dnsx A 记录查询完成：命中 %d/%d", len(dnsxIPsByHost), len(subdomains)),
	}
	ipGeoMap := lookupIPGeoMap(ctx, dnsxIPsByHost, events)
	for _, host := range subdomains {
		ips := dnsxIPsByHost[host]
		baseSources := append([]string{}, sourceMap[host]...)
		events <- Event{
			Type:     EventRecord,
			Time:     time.Now(),
			TaskType: model.TaskPipeline,
			Provider: "result_classifier",
			Record: model.Record{
				Value:     host,
				TaskType:  model.TaskPipeline,
				Query:     rootDomain,
				Sources:   append([]string{"result_type:all_domains"}, baseSources...),
				FirstSeen: time.Now(),
			},
			IsNew: true,
		}
		if len(ips) > 0 && !allPrivateOrReserved(ips) {
			events <- Event{
				Type:     EventRecord,
				Time:     time.Now(),
				TaskType: model.TaskPipeline,
				Provider: "result_classifier",
				Record: model.Record{
					Value:     formatResolvedWithGeo(host, ips, ipGeoMap),
					TaskType:  model.TaskPipeline,
					Query:     rootDomain,
					Sources:   append([]string{"result_type:resolved_ok", "dnsx_a"}, baseSources...),
					FirstSeen: time.Now(),
				},
				IsNew: true,
			}
		} else {
			reason := "无A记录"
			if len(ips) > 0 {
				reason = fmt.Sprintf("保留/内网IP(%s)", strings.Join(ips, ","))
			}
			events <- Event{
				Type:     EventRecord,
				Time:     time.Now(),
				TaskType: model.TaskPipeline,
				Provider: "result_classifier",
				Record: model.Record{
					Value:     fmt.Sprintf("%s | 问题=%s", host, reason),
					TaskType:  model.TaskPipeline,
					Query:     rootDomain,
					Sources:   append([]string{"result_type:resolve_abnormal", "dnsx_a"}, baseSources...),
					FirstSeen: time.Now(),
				},
				IsNew: true,
			}
		}
	}

	if prober == nil {
		events <- Event{
			Type:     EventTaskDone,
			Time:     time.Now(),
			TaskType: model.TaskPipeline,
			Message:  "全流程完成（未启用 Web 探测）",
		}
		return
	}

	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Message:  "步骤3/4：异常域名 hosts 碰撞 + Web 探测与指纹识别",
	}
	rawCount := 0
	uniqueCount := 0
	webDedup := map[string]struct{}{}
	dnsxAllIPs := flattenIPMap(dnsxIPsByHost)
	allCollectedIPs := mergeUniqueIPs(apiAllIPs, dnsxAllIPs)
	if !enableHostsCollision {
		events <- Event{
			Type:     EventLog,
			Time:     time.Now(),
			TaskType: model.TaskPipeline,
			Provider: "hosts_collision",
			Message:  "hosts 碰撞已关闭，仅对当前解析正常域名做常规 Web 探测",
		}
	}
	abnormalTotal := 0
	for _, host := range subdomains {
		currentIPs := dnsxIPsByHost[host]
		if len(currentIPs) == 0 || allPrivateOrReserved(currentIPs) {
			abnormalTotal++
		}
	}
	abnormalDone := 0

	for _, host := range subdomains {
		select {
		case <-ctx.Done():
			events <- Event{Type: EventTaskDone, Time: time.Now(), TaskType: model.TaskPipeline, Message: "全流程已取消"}
			return
		default:
		}

		currentIPs := dnsxIPsByHost[host]
		abnormal := len(currentIPs) == 0 || allPrivateOrReserved(currentIPs)

		if abnormal {
			abnormalDone++
			if enableHostsCollision {
				events <- Event{
					Type:     EventLog,
					Time:     time.Now(),
					TaskType: model.TaskPipeline,
					Provider: "hosts_collision",
					Message:  fmt.Sprintf("hosts 碰撞进度 %d/%d：%s（候选IP %d）", abnormalDone, abnormalTotal, host, len(allCollectedIPs)),
				}
			}
			if !enableHostsCollision {
				continue
			}
			candidates := allCollectedIPs
			for _, ip := range candidates {
				for _, scheme := range []string{"https", "http"} {
					res := prober.ProbeHostCollision(ctx, scheme, host, ip)
					rawCount++
					if res.Error != "" || res.StatusCode == 0 {
						continue
					}
					key := strings.ToLower(res.Host) + "|" + res.TargetURL
					if _, exists := webDedup[key]; exists {
						continue
					}
					webDedup[key] = struct{}{}
					uniqueCount++
					events <- Event{
						Type:     EventRecord,
						Time:     time.Now(),
						TaskType: model.TaskWebProbe,
						Provider: "hosts_collision",
						IP:       res.ResolvedIP,
						Record: model.Record{
							Value:     formatProbeValue(res),
							TaskType:  model.TaskWebProbe,
							Query:     host,
							Sources:   append([]string{"hosts_collision", "api_query_ip"}, sourceMap[host]...),
							FirstSeen: time.Now(),
						},
						IsNew:     true,
						RawCount:  rawCount,
						UniqueCnt: uniqueCount,
					}
					events <- Event{
						Type:     EventLog,
						Time:     time.Now(),
						TaskType: model.TaskPipeline,
						Provider: "hosts_collision",
						Message:  fmt.Sprintf("命中结果：%s", formatProbeValue(res)),
					}
				}
			}
			continue
		}

		res := prober.ProbeHostAuto(ctx, host)
		rawCount++
		if res.Error != "" || res.StatusCode == 0 {
			continue
		}
		key := strings.ToLower(res.Host) + "|" + res.TargetURL
		if _, exists := webDedup[key]; exists {
			continue
		}
		webDedup[key] = struct{}{}
		uniqueCount++
		events <- Event{
			Type:     EventRecord,
			Time:     time.Now(),
			TaskType: model.TaskWebProbe,
			Provider: "web_probe",
			IP:       firstIP(currentIPs),
			Record: model.Record{
				Value:     formatProbeValue(res),
				TaskType:  model.TaskWebProbe,
				Query:     host,
				Sources:   append([]string{"web_probe", "dnsx_a"}, sourceMap[host]...),
				FirstSeen: time.Now(),
			},
			IsNew:     true,
			RawCount:  rawCount,
			UniqueCnt: uniqueCount,
		}
		events <- Event{
			Type:     EventLog,
			Time:     time.Now(),
			TaskType: model.TaskPipeline,
			Provider: "web_probe",
			Message:  fmt.Sprintf("命中结果：%s", formatProbeValue(res)),
		}
	}

	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Message:  "步骤4/4：汇总结果",
	}
	events <- Event{
		Type:      EventTaskDone,
		Time:      time.Now(),
		TaskType:  model.TaskPipeline,
		RawCount:  rawCount,
		UniqueCnt: uniqueCount,
		Message:   fmt.Sprintf("全流程完成：探测原始 %d 条，去重 %d 条", rawCount, uniqueCount),
	}
}

func (o *Orchestrator) collectSubdomains(
	ctx context.Context,
	rootDomain string,
	subProviders []providers.SubdomainProvider,
	events chan<- Event,
) ([]string, map[string][]string, map[string][]string) {
	sem := make(chan struct{}, o.maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	hosts := map[string][]string{}
	ipsByHost := map[string][]string{}

	for _, provider := range subProviders {
		p := provider
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			start := time.Now()
			events <- Event{Type: EventLog, Time: time.Now(), TaskType: model.TaskPipeline, Provider: p.Name(), Message: fmt.Sprintf("%s 开始调用：query=%s", p.Name(), rootDomain)}
			records := make([]providers.SubdomainRecord, 0, 64)
			if rp, ok := p.(providers.SubdomainRecordProvider); ok {
				rs, err := rp.CollectSubdomainRecords(ctx, rootDomain)
				if err != nil {
					events <- Event{Type: EventLog, Time: time.Now(), TaskType: model.TaskPipeline, Provider: p.Name(), Message: fmt.Sprintf("%s 查询失败: %v", p.Name(), err), Err: err}
					return
				}
				records = rs
			} else {
				values, err := p.CollectSubdomains(ctx, rootDomain)
				if err != nil {
					events <- Event{Type: EventLog, Time: time.Now(), TaskType: model.TaskPipeline, Provider: p.Name(), Message: fmt.Sprintf("%s 查询失败: %v", p.Name(), err), Err: err}
					return
				}
				for _, host := range values {
					records = append(records, providers.SubdomainRecord{Host: host})
				}
			}
			raw := len(records)
			added := 0
			apiIPCnt := 0
			mu.Lock()
			for _, rec := range records {
				host := strings.ToLower(strings.TrimSpace(rec.Host))
				if host == "" {
					continue
				}
				if len(hosts[host]) == 0 {
					added++
				}
				if !containsStr(hosts[host], p.Name()) {
					hosts[host] = append(hosts[host], p.Name())
				}
				ip := strings.TrimSpace(rec.IP)
				if ip != "" {
					oldLen := len(ipsByHost[host])
					ipsByHost[host] = mergeUniqueIPs(ipsByHost[host], []string{ip})
					if len(ipsByHost[host]) > oldLen {
						apiIPCnt++
					}
				}
			}
			total := len(hosts)
			mu.Unlock()
			events <- Event{
				Type:     EventLog,
				Time:     time.Now(),
				TaskType: model.TaskPipeline,
				Provider: p.Name(),
				Message:  fmt.Sprintf("%s 子域名获取 %d 条，新增 %d 条，累计去重 %d 条，API查询IP新增 %d 条，耗时 %s，样例 %s", p.Name(), raw, added, total, apiIPCnt, time.Since(start).Round(time.Millisecond), sampleSubdomainHosts(records, 3)),
			}
			if p.Name() == "myssl" && raw == 0 {
				events <- Event{
					Type:     EventLog,
					Time:     time.Now(),
					TaskType: model.TaskPipeline,
					Provider: p.Name(),
					Message:  "myssl 当前返回为空（接口成功但无数据），通常与目标域名在其数据源覆盖度有关",
				}
			}
		}()
	}
	wg.Wait()

	all := make([]string, 0, len(hosts))
	for h := range hosts {
		all = append(all, h)
	}
	sort.Strings(all)
	return all, hosts, ipsByHost
}

func (o *Orchestrator) collectProviderAPIIPs(
	ctx context.Context,
	rootDomain string,
	hostIPProviders []domainips.HostIPProvider,
	events chan<- Event,
) map[string][]string {
	out := map[string][]string{}
	for _, p := range hostIPProviders {
		start := time.Now()
		events <- Event{Type: EventLog, Time: time.Now(), TaskType: model.TaskPipeline, Provider: p.Name(), Message: fmt.Sprintf("%s API 查询 IP 开始：query=%s", p.Name(), rootDomain)}
		m, err := p.CollectHostIPs(ctx, rootDomain)
		if err != nil {
			events <- Event{Type: EventLog, Time: time.Now(), TaskType: model.TaskPipeline, Provider: p.Name(), Message: fmt.Sprintf("%s 查询失败: %v", p.Name(), err), Err: err}
			continue
		}
		count := len(m)
		for host, ips := range m {
			out[host] = mergeUniqueIPs(out[host], ips)
		}
		events <- Event{Type: EventLog, Time: time.Now(), TaskType: model.TaskPipeline, Provider: p.Name(), Message: fmt.Sprintf("%s API 查询 IP 获取 %d 条，耗时 %s，样例 %s", p.Name(), count, time.Since(start).Round(time.Millisecond), sampleHostIPMap(m, 2))}
	}
	return out
}

func mergeUniqueIPs(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, x := range append(a, b...) {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func allPrivateOrReserved(ips []string) bool {
	if len(ips) == 0 {
		return true
	}
	for _, ip := range ips {
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil {
			continue
		}
		if !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsMulticast() {
			return false
		}
	}
	return true
}

type ipGeoInfo struct {
	Country  string
	Region   string
	Operator string
}

func formatResolvedWithGeo(host string, ips []string, geoMap map[string]ipGeoInfo) string {
	if len(ips) == 0 {
		return fmt.Sprintf("%s | IP=- | 国家=- | 地区=- | 运营商=-", host)
	}
	countries := make([]string, 0, 2)
	regions := make([]string, 0, 2)
	operators := make([]string, 0, 2)
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		geo, ok := geoMap[ip]
		if !ok {
			continue
		}
		countries = appendUnique(countries, geo.Country)
		regions = appendUnique(regions, geo.Region)
		operators = appendUnique(operators, geo.Operator)
	}
	sort.Strings(countries)
	sort.Strings(regions)
	sort.Strings(operators)
	return fmt.Sprintf(
		"%s | IP=%s | 国家=%s | 地区=%s | 运营商=%s",
		host,
		strings.Join(ips, ","),
		joinOrDash(countries),
		joinOrDash(regions),
		joinOrDash(operators),
	)
}

func lookupIPGeoMap(ctx context.Context, ipsByHost map[string][]string, events chan<- Event) map[string]ipGeoInfo {
	merged := flattenIPMap(ipsByHost)
	uniquePublic := make([]string, 0, len(merged))
	for _, raw := range merged {
		ip := strings.TrimSpace(raw)
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
			continue
		}
		uniquePublic = append(uniquePublic, ip)
	}
	out := make(map[string]ipGeoInfo, len(uniquePublic))
	if len(uniquePublic) == 0 {
		return out
	}
	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Provider: "ipwhois",
		Message:  fmt.Sprintf("IP 归属地查询开始：目标 %d 个", len(uniquePublic)),
	}
	client := &http.Client{Timeout: 8 * time.Second}
	okCount := 0
	for _, ip := range uniquePublic {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		geo, err := queryIPGeo(ctx, client, ip)
		if err != nil {
			continue
		}
		if geo.Country == "" && geo.Region == "" && geo.Operator == "" {
			continue
		}
		out[ip] = geo
		okCount++
	}
	events <- Event{
		Type:     EventLog,
		Time:     time.Now(),
		TaskType: model.TaskPipeline,
		Provider: "ipwhois",
		Message:  fmt.Sprintf("IP 归属地查询完成：成功 %d/%d", okCount, len(uniquePublic)),
	}
	return out
}

func queryIPGeo(ctx context.Context, client *http.Client, ip string) (ipGeoInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipwho.is/"+ip+"?lang=zh", nil)
	if err != nil {
		return ipGeoInfo{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ipGeoInfo{}, err
	}
	defer resp.Body.Close()
	var data struct {
		Success    bool   `json:"success"`
		Country    string `json:"country"`
		Region     string `json:"region"`
		City       string `json:"city"`
		Connection struct {
			ISP string `json:"isp"`
			Org string `json:"org"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ipGeoInfo{}, err
	}
	if !data.Success {
		return ipGeoInfo{}, nil
	}
	country := normalizeGeoZh(data.Country)
	region := normalizeGeoZh(data.Region)
	org := normalizeGeoZh(data.Connection.ISP)
	if org == "" {
		org = normalizeGeoZh(data.Connection.Org)
	}
	return ipGeoInfo{
		Country:  country,
		Region:   region,
		Operator: org,
	}, nil
}

func compactParts(parts ...string) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func appendUnique(list []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return list
	}
	for _, x := range list {
		if x == value {
			return list
		}
	}
	return append(list, value)
}

func joinOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, "/")
}

func normalizeGeoZh(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"Cambodia", "柬埔寨",
		"Phnom Penh", "金边",
		"Phnom Phen City", "金边",
	)
	return replacer.Replace(v)
}

func formatProbeValue(r probe.Result) string {
	tech := strings.Join(r.Technologies, "|")
	if tech == "" {
		tech = "-"
	}
	title := r.Title
	if title == "" {
		title = "-"
	}
	return fmt.Sprintf("URL=%s | 状态=%d | 标题=%s | 技术=%s", r.TargetURL, r.StatusCode, title, tech)
}

func containsStr(list []string, value string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}
	return false
}

func flattenIPMap(m map[string][]string) []string {
	merged := make([]string, 0, 128)
	for _, ips := range m {
		merged = mergeUniqueIPs(merged, ips)
	}
	return merged
}

func firstIP(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	return strings.TrimSpace(ips[0])
}

func sampleSubdomainHosts(records []providers.SubdomainRecord, n int) string {
	if len(records) == 0 {
		return "-"
	}
	maxN := n
	if len(records) < maxN {
		maxN = len(records)
	}
	parts := make([]string, 0, maxN)
	for i := 0; i < maxN; i++ {
		h := strings.TrimSpace(records[i].Host)
		if h != "" {
			parts = append(parts, h)
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}

func sampleHostIPMap(m map[string][]string, n int) string {
	if len(m) == 0 {
		return "-"
	}
	hosts := make([]string, 0, len(m))
	for h := range m {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	maxN := n
	if len(hosts) < maxN {
		maxN = len(hosts)
	}
	parts := make([]string, 0, maxN)
	for i := 0; i < maxN; i++ {
		h := hosts[i]
		parts = append(parts, fmt.Sprintf("%s=%s", h, strings.Join(m[h], "|")))
	}
	return strings.Join(parts, ",")
}
