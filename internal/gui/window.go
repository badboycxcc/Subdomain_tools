package gui

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	appstate "subdomain-tools/internal/app"
	"subdomain-tools/internal/collect"
	"subdomain-tools/internal/config"
	"subdomain-tools/internal/core/exporter"
	"subdomain-tools/internal/core/model"
	"subdomain-tools/internal/core/netx"
	"subdomain-tools/internal/core/probe"
	"subdomain-tools/internal/core/store"
	"subdomain-tools/internal/providers"
	"subdomain-tools/internal/providers/domainips"
	"subdomain-tools/internal/providers/reverseip"
	"subdomain-tools/internal/providers/subdomains"
)

type AppWindow struct {
	app    fyne.App
	window fyne.Window

	mu       sync.Mutex
	settings config.Settings
	state    *appstate.State
}

func New() (*AppWindow, error) {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultSettings()
	}
	app := fyneapp.NewWithID("subdomain-tools")
	app.Settings().SetTheme(theme.LightTheme())
	w := app.NewWindow("Subdomain Tools MVP")
	w.Resize(fyne.NewSize(900, 580))
	w.SetFixedSize(true)

	memStore := store.NewMemoryStore()
	state := appstate.NewState(memStore)

	return &AppWindow{
		app:      app,
		window:   w,
		settings: cfg,
		state:    state,
	}, nil
}

func (aw *AppWindow) Run() {
	aw.window.SetContent(aw.buildTabs())
	aw.window.ShowAndRun()
}

func (aw *AppWindow) buildTabs() fyne.CanvasObject {
	// Shared widgets
	statusLabel := widget.NewLabel("状态: 空闲")
	counterLabel := widget.NewLabel("原始: 0 / 去重: 0")
	resultsArea := widget.NewMultiLineEntry()
	resultsArea.Wrapping = fyne.TextWrapWord
	resultsArea.Scroll = fyne.ScrollVerticalOnly
	resultsArea.TextStyle = fyne.TextStyle{}
	resultsArea.SetMinRowsVisible(20)
	logArea := widget.NewMultiLineEntry()
	logArea.Wrapping = fyne.TextWrapWord
	logArea.Scroll = fyne.ScrollVerticalOnly
	logArea.TextStyle = fyne.TextStyle{}
	logArea.SetMinRowsVisible(20)
	lastLogText := ""
	logArea.OnChanged = func(s string) {
		// Keep logs read-only while preserving normal text color/rendering.
		if s != lastLogText {
			logArea.SetText(lastLogText)
		}
	}

	// Subdomain tab
	domainEntry := widget.NewEntry()
	domainEntry.SetPlaceHolder("example.com")
	subStartBtn := widget.NewButton("开始收集", nil)
	pipelineStartBtn := widget.NewButton("开始全流程", nil)
	subCancelBtn := widget.NewButton("取消", nil)
	subCancelBtn.Disable()

	subTab := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("输入根域名"),
			domainEntry,
			container.NewHBox(subStartBtn, pipelineStartBtn, subCancelBtn, statusLabel, counterLabel),
		),
		nil, nil, nil,
		resultsArea,
	)

	// Reverse IP tab
	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("1.1.1.1")
	rStartBtn := widget.NewButton("开始反查", nil)
	rCancelBtn := widget.NewButton("取消", nil)
	rCancelBtn.Disable()

	reverseTab := container.NewBorder(
		container.NewVBox(
			widget.NewLabel("输入 IP"),
			ipEntry,
			container.NewHBox(rStartBtn, rCancelBtn),
		),
		nil, nil, nil,
		widget.NewLabel("执行后结果会同步更新到 Results 标签"),
	)

	// Results tab
	filterEntry := widget.NewEntry()
	filterEntry.SetPlaceHolder("按关键字过滤")
	resultTypeSelect := widget.NewSelect(
		[]string{"汇总视图", "全部记录", "全部域名", "当前解析正确域名+IP", "解析有问题域名"},
		nil,
	)
	resultTypeSelect.SetSelected("汇总视图")
	exportTxtBtn := widget.NewButton("导出 TXT", nil)
	exportCsvBtn := widget.NewButton("导出 CSV", nil)
	exportJSONBtn := widget.NewButton("导出 JSON", nil)

	resultsList := widget.NewMultiLineEntry()
	resultsList.Wrapping = fyne.TextWrapWord
	resultsList.Scroll = fyne.ScrollVerticalOnly
	resultsList.TextStyle = fyne.TextStyle{}
	resultsList.SetMinRowsVisible(20)

	resultTab := container.NewBorder(
		container.NewVBox(
			filterEntry,
			resultTypeSelect,
			container.NewHBox(exportTxtBtn, exportCsvBtn, exportJSONBtn),
		),
		nil, nil, nil,
		resultsList,
	)

	// Settings tab
	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetText(strconv.Itoa(aw.settings.HTTPTimeoutSecond))
	concurrencyEntry := widget.NewEntry()
	concurrencyEntry.SetText(strconv.Itoa(aw.settings.MaxConcurrency))
	retryEntry := widget.NewEntry()
	retryEntry.SetText(strconv.Itoa(aw.settings.MaxRetries))
	rapidDNSKeyEntry := widget.NewPasswordEntry()
	rapidDNSKeyEntry.SetText(strings.TrimSpace(aw.settings.RapidDNSAPIKey))
	dnsResolversEntry := widget.NewEntry()
	dnsResolversEntry.SetPlaceHolder("1.1.1.1:53,8.8.8.8:53")
	dnsResolversEntry.SetText(strings.Join(aw.settings.DNSResolvers, ","))
	hostsCollisionCheck := widget.NewCheck("", nil)
	hostsCollisionCheck.SetChecked(aw.settings.EnableHostsCollision)
	webProbeCheck := widget.NewCheck("", nil)
	webProbeCheck.SetChecked(aw.settings.EnableWebProbe)
	saveSettingsBtn := widget.NewButton("保存设置", nil)

	settingsTab := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("HTTP 超时(秒)", timeoutEntry),
			widget.NewFormItem("最大并发", concurrencyEntry),
			widget.NewFormItem("重试次数", retryEntry),
			widget.NewFormItem("RapidDNS API Key", rapidDNSKeyEntry),
			widget.NewFormItem("DNS 解析器(逗号分隔)", dnsResolversEntry),
			widget.NewFormItem("启用 hosts 碰撞", hostsCollisionCheck),
			widget.NewFormItem("启用 Web 指纹探测", webProbeCheck),
		),
		saveSettingsBtn,
	)

	// Logs tab
	logTab := container.NewBorder(nil, nil, nil, nil, logArea)

	refreshResults := func(keyword string) {
		records := aw.state.Store.All()
		if resultTypeSelect.Selected == "汇总视图" {
			resultsList.SetText(buildPipelineSummaryText(records, keyword))
			return
		}
		records = filterResultRecords(records, resultTypeSelect.Selected, keyword)
		var b strings.Builder
		for _, r := range records {
			b.WriteString(fmt.Sprintf("[%s] %s\n", taskTypeName(r.TaskType), r.Value))
		}
		resultsList.SetText(b.String())
	}

	refreshLogs := func() {
		logs := aw.state.SnapshotLogs()
		var b strings.Builder
		for _, l := range logs {
			b.WriteString(fmt.Sprintf("%s [%s] %s\n", l.Time.Format("15:04:05"), l.Level, l.Message))
		}
		lastLogText = b.String()
		logArea.SetText(lastLogText)
	}

	runTask := func(taskType model.TaskType, query string) {
		query = strings.TrimSpace(query)
		if query == "" {
			dialog.ShowInformation("提示", "输入不能为空", aw.window)
			return
		}
		aw.state.Store.Clear()
		resultsArea.SetText("")
		refreshResults("")

		ctx, cancel := context.WithCancel(context.Background())
		aw.mu.Lock()
		aw.state.Running = true
		aw.state.CurrentTask = taskType
		aw.state.CurrentQuery = query
		aw.state.Cancel = cancel
		aw.state.RawCount = 0
		aw.state.UniqueCount = 0
		aw.state.ProviderState = map[string]model.ProviderStatus{}
		aw.mu.Unlock()

		statusLabel.SetText("状态: 运行中")
		counterLabel.SetText("原始: 0 / 去重: 0")
		subStartBtn.Disable()
		pipelineStartBtn.Disable()
		rStartBtn.Disable()
		subCancelBtn.Enable()
		rCancelBtn.Enable()

		client := netx.NewHTTPClient(aw.settings.HTTPTimeout())
		orchestrator := collect.NewOrchestrator(aw.settings.MaxConcurrency)
		var events <-chan collect.Event

		if taskType == model.TaskSubdomain {
			subPS := aw.buildSubdomainProviders(client)
			names := make([]string, 0, len(subPS))
			for _, p := range subPS {
				names = append(names, p.Name())
			}
			aw.state.AppendLog(model.LogEntry{
				Time:    time.Now(),
				Level:   "信息",
				Message: fmt.Sprintf("已启用子域名源: %s", strings.Join(names, ",")),
			})
			events = orchestrator.RunSubdomainTask(ctx, query, subPS)
		} else if taskType == model.TaskPipeline {
			var proberInstance *probe.Prober
			if aw.settings.EnableWebProbe {
				p, err := probe.NewProber(aw.settings.HTTPTimeout())
				if err != nil {
					dialog.ShowError(err, aw.window)
					subStartBtn.Enable()
					pipelineStartBtn.Enable()
					rStartBtn.Enable()
					subCancelBtn.Disable()
					rCancelBtn.Disable()
					return
				}
				proberInstance = p
			}
			subPS := aw.buildSubdomainProviders(client)
			names := make([]string, 0, len(subPS))
			for _, p := range subPS {
				names = append(names, p.Name())
			}
			aw.state.AppendLog(model.LogEntry{
				Time:    time.Now(),
				Level:   "信息",
				Message: fmt.Sprintf("已启用子域名源: %s", strings.Join(names, ",")),
			})
			events = orchestrator.RunPipelineTask(
				ctx,
				query,
				subPS,
				aw.buildHostIPProviders(client),
				proberInstance,
				aw.settings.DNSResolvers,
				aw.settings.EnableHostsCollision,
			)
		} else {
			events = orchestrator.RunReverseIPTask(ctx, query, aw.buildReverseIPProviders(client))
		}

		go func() {
			for evt := range events {
				evtCopy := evt
				fyne.Do(func() {
					aw.consumeEvent(evtCopy, statusLabel, counterLabel, resultsArea, filterEntry.Text, refreshResults, refreshLogs)
					if evtCopy.Type == collect.EventTaskDone {
						subStartBtn.Enable()
						pipelineStartBtn.Enable()
						rStartBtn.Enable()
						subCancelBtn.Disable()
						rCancelBtn.Disable()
					}
				})
			}
		}()
	}

	subStartBtn.OnTapped = func() {
		runTask(model.TaskSubdomain, domainEntry.Text)
	}
	pipelineStartBtn.OnTapped = func() {
		runTask(model.TaskPipeline, domainEntry.Text)
	}
	rStartBtn.OnTapped = func() {
		runTask(model.TaskReverseIP, ipEntry.Text)
	}
	subCancelBtn.OnTapped = func() {
		aw.cancelTask(statusLabel)
	}
	rCancelBtn.OnTapped = func() {
		aw.cancelTask(statusLabel)
	}
	filterEntry.OnChanged = func(s string) {
		refreshResults(s)
	}
	resultTypeSelect.OnChanged = func(_ string) {
		refreshResults(filterEntry.Text)
	}
	saveSettingsBtn.OnTapped = func() {
		timeout, err := strconv.Atoi(strings.TrimSpace(timeoutEntry.Text))
		if err != nil || timeout <= 0 {
			dialog.ShowError(fmt.Errorf("超时值无效"), aw.window)
			return
		}
		concurrency, err := strconv.Atoi(strings.TrimSpace(concurrencyEntry.Text))
		if err != nil || concurrency <= 0 {
			dialog.ShowError(fmt.Errorf("并发值无效"), aw.window)
			return
		}
		retry, err := strconv.Atoi(strings.TrimSpace(retryEntry.Text))
		if err != nil || retry < 0 {
			dialog.ShowError(fmt.Errorf("重试值无效"), aw.window)
			return
		}
		aw.settings.HTTPTimeoutSecond = timeout
		aw.settings.MaxConcurrency = concurrency
		aw.settings.MaxRetries = retry
		aw.settings.RapidDNSAPIKey = strings.TrimSpace(rapidDNSKeyEntry.Text)
		aw.settings.DNSResolvers = parseDNSResolversInput(dnsResolversEntry.Text)
		aw.settings.EnableHostsCollision = hostsCollisionCheck.Checked
		aw.settings.EnableWebProbe = webProbeCheck.Checked
		if err := config.Save(aw.settings); err != nil {
			dialog.ShowError(err, aw.window)
			return
		}
		dialog.ShowInformation("提示", "设置已保存", aw.window)
	}

	export := func(format exporter.Format) {
		records := aw.state.Store.All()
		isSummaryTXT := resultTypeSelect.Selected == "汇总视图" && format == exporter.FormatTXT
		if resultTypeSelect.Selected != "汇总视图" {
			records = filterResultRecords(records, resultTypeSelect.Selected, filterEntry.Text)
		} else {
			records = filterResultRecords(records, "全部记录", filterEntry.Text)
		}
		if len(records) == 0 {
			dialog.ShowInformation("提示", "没有可导出的结果", aw.window)
			return
		}
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil || uri == nil {
				return
			}
			path := exporter.BuildExportPath(uri.Path(), format)
			if isSummaryTXT {
				summaryText := buildPipelineSummaryText(records, filterEntry.Text)
				if err := os.WriteFile(path, []byte(summaryText), 0o644); err != nil {
					dialog.ShowError(err, aw.window)
					return
				}
			} else if err := exporter.Export(path, records, format); err != nil {
				dialog.ShowError(err, aw.window)
				return
			}
			dialog.ShowInformation("导出成功", filepath.Base(path), aw.window)
		}, aw.window)
	}
	exportTxtBtn.OnTapped = func() { export(exporter.FormatTXT) }
	exportCsvBtn.OnTapped = func() { export(exporter.FormatCSV) }
	exportJSONBtn.OnTapped = func() { export(exporter.FormatJSON) }

	tabs := container.NewAppTabs(
		container.NewTabItem("Subdomains", subTab),
		container.NewTabItem("Reverse IP", reverseTab),
		container.NewTabItem("Results", resultTab),
		container.NewTabItem("Settings", settingsTab),
		container.NewTabItem("Logs", logTab),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	return tabs
}

func (aw *AppWindow) consumeEvent(
	evt collect.Event,
	statusLabel *widget.Label,
	counterLabel *widget.Label,
	resultsArea *widget.Entry,
	filterKeyword string,
	refreshResults func(string),
	refreshLogs func(),
) {
	aw.mu.Lock()
	defer aw.mu.Unlock()

	switch evt.Type {
	case collect.EventRecord:
		// Keep counters stable when synthetic classifier records don't carry counts.
		if evt.RawCount > 0 || evt.UniqueCnt > 0 {
			aw.state.RawCount = evt.RawCount
			aw.state.UniqueCount = evt.UniqueCnt
		}
		aw.state.Store.AddBatch([]model.Record{evt.Record})
		if evt.Provider != "result_classifier" {
			logMsg := formatOutputLine(evt.Record, evt.IsNew)
			if evt.IP != "" {
				logMsg += " | IP=" + evt.IP
			}
			if evt.Provider != "" {
				logMsg += " | 来源=" + evt.Provider
			}
			aw.state.AppendLog(model.LogEntry{
				Time:    evt.Time,
				Level:   "信息",
				Message: logMsg,
			})
		}
		// Subdomains 输出区只展示去重结果，详细过程统一看 Logs。
		if evt.IsNew && (aw.state.CurrentTask == model.TaskSubdomain || evt.TaskType == model.TaskWebProbe) {
			resultsArea.SetText(resultsArea.Text + evt.Record.Value + "\n")
		}
	case collect.EventProviderDone:
		ps := aw.state.ProviderState[evt.Provider]
		ps.Name = evt.Provider
		ps.Running = false
		if evt.Err != nil {
			ps.Error = evt.Err.Error()
		}
		aw.state.ProviderState[evt.Provider] = ps
		aw.state.AppendLog(model.LogEntry{
			Time:    evt.Time,
			Level:   logLevel(evt.Err),
			Message: evt.Message,
		})
	case collect.EventLog:
		aw.state.AppendLog(model.LogEntry{
			Time:    evt.Time,
			Level:   logLevel(evt.Err),
			Message: evt.Message,
		})
	case collect.EventTaskDone:
		aw.state.Running = false
		aw.state.Cancel = nil
		statusLabel.SetText("状态: 已完成")
		aw.state.AppendLog(model.LogEntry{
			Time:    evt.Time,
			Level:   "信息",
			Message: evt.Message,
		})
	}
	counterLabel.SetText(fmt.Sprintf("原始: %d / 去重: %d", aw.state.RawCount, aw.state.UniqueCount))
	// Classifier records can be high-volume; defer list rebuild to filter change or task completion.
	if !(evt.Type == collect.EventRecord && evt.Provider == "result_classifier") {
		refreshResults(filterKeyword)
	}
	refreshLogs()
}

func (aw *AppWindow) cancelTask(statusLabel *widget.Label) {
	aw.mu.Lock()
	defer aw.mu.Unlock()
	if aw.state.Cancel != nil {
		aw.state.Cancel()
		aw.state.Cancel = nil
		aw.state.Running = false
		statusLabel.SetText("状态: 已取消")
		aw.state.AppendLog(model.LogEntry{
			Time:    time.Now(),
			Level:   "警告",
			Message: "任务已由用户取消",
		})
	}
}

func (aw *AppWindow) buildSubdomainProviders(client *http.Client) []providers.SubdomainProvider {
	ps := []providers.SubdomainProvider{
		subdomains.NewSubfinderSDKProvider(aw.settings),
		subdomains.NewIPTHCSubdomainProvider(client, aw.settings),
		subdomains.NewHackerTargetHostSearchSubdomainProvider(client, aw.settings),
		subdomains.NewURLScanProvider(client, aw.settings),
		subdomains.NewMySSLProvider(client, aw.settings),
	}
	if strings.TrimSpace(aw.settings.RapidDNSAPIKey) != "" {
		ps = append(ps, subdomains.NewRapidDNSProvider(client, aw.settings))
	}
	return ps
}

func (aw *AppWindow) buildReverseIPProviders(client *http.Client) []providers.ReverseIPProvider {
	return []providers.ReverseIPProvider{
		reverseip.NewIPTHCProvider(client, aw.settings),
		reverseip.NewHackerTargetProvider(client, aw.settings),
		reverseip.NewURLScanProvider(client, aw.settings),
	}
}

func (aw *AppWindow) buildHostIPProviders(client *http.Client) []domainips.HostIPProvider {
	return []domainips.HostIPProvider{
		domainips.NewHackerTargetHostSearchProvider(client, aw.settings),
	}
}

func logLevel(err error) string {
	if err != nil {
		return "错误"
	}
	return "信息"
}

func taskTypeName(t model.TaskType) string {
	switch t {
	case model.TaskSubdomain:
		return "子域名"
	case model.TaskReverseIP:
		return "反查"
	case model.TaskWebProbe:
		return "Web探测"
	case model.TaskPipeline:
		return "全流程"
	default:
		return string(t)
	}
}

func formatOutputLine(r model.Record, isNew bool) string {
	if isNew {
		return fmt.Sprintf("[%s] %s", taskTypeName(r.TaskType), r.Value)
	}
	return fmt.Sprintf("[%s][重复] %s", taskTypeName(r.TaskType), r.Value)
}

func parseDNSResolversInput(s string) []string {
	raw := strings.NewReplacer("\r\n", ",", "\n", ",", ";", ",").Replace(strings.TrimSpace(s))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func filterResultRecords(records []model.Record, resultType string, keyword string) []model.Record {
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	out := make([]model.Record, 0, len(records))
	for _, r := range records {
		if !matchResultType(r, resultType) {
			continue
		}
		if keyword != "" {
			text := strings.ToLower(r.Value + " " + r.Query + " " + strings.Join(r.Sources, ","))
			if !strings.Contains(text, keyword) {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func matchResultType(r model.Record, resultType string) bool {
	switch resultType {
	case "全部域名":
		return hasSourceTag(r.Sources, "result_type:all_domains")
	case "当前解析正确域名+IP":
		return hasSourceTag(r.Sources, "result_type:resolved_ok")
	case "解析有问题域名":
		return hasSourceTag(r.Sources, "result_type:resolve_abnormal")
	default:
		return true
	}
}

func hasSourceTag(sources []string, tag string) bool {
	for _, s := range sources {
		if strings.EqualFold(strings.TrimSpace(s), tag) {
			return true
		}
	}
	return false
}

func buildPipelineSummaryText(records []model.Record, keyword string) string {
	kw := strings.ToLower(strings.TrimSpace(keyword))
	allDomains := make([]string, 0, 128)
	resolved := make([]string, 0, 128)
	abnormal := make([]string, 0, 128)
	webProbe := make([]string, 0, 64)
	uniqueIPs := make([]string, 0, 128)
	seenIP := map[string]struct{}{}
	cBlocks := make([]string, 0, 64)
	seenC := map[string]struct{}{}
	countriesByC := map[string]map[string]struct{}{}
	regionsByC := map[string]map[string]struct{}{}
	operatorsByC := map[string]map[string]struct{}{}

	for _, r := range records {
		line := strings.TrimSpace(r.Value)
		if line == "" {
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(line), kw) {
			continue
		}
		if hasSourceTag(r.Sources, "result_type:all_domains") {
			allDomains = append(allDomains, line)
			continue
		}
		if hasSourceTag(r.Sources, "result_type:resolved_ok") {
			resolved = append(resolved, line)
			ips := extractIPsFromResolvedLine(line)
			for _, ip := range ips {
				if _, ok := seenIP[ip]; !ok {
					seenIP[ip] = struct{}{}
					uniqueIPs = append(uniqueIPs, ip)
				}
				if c := toIPv4CBlock(ip); c != "" {
					if _, ok := seenC[c]; !ok {
						seenC[c] = struct{}{}
						cBlocks = append(cBlocks, c)
					}
					country, region, operator := parseGeoColumns(extractGeoInfoForIP(line, ip))
					if country != "" {
						if countriesByC[c] == nil {
							countriesByC[c] = map[string]struct{}{}
						}
						countriesByC[c][country] = struct{}{}
					}
					if region != "" {
						if regionsByC[c] == nil {
							regionsByC[c] = map[string]struct{}{}
						}
						regionsByC[c][region] = struct{}{}
					}
					if operator != "" {
						if operatorsByC[c] == nil {
							operatorsByC[c] = map[string]struct{}{}
						}
						operatorsByC[c][operator] = struct{}{}
					}
				}
			}
			continue
		}
		if hasSourceTag(r.Sources, "result_type:resolve_abnormal") {
			abnormal = append(abnormal, line)
			continue
		}
		if r.TaskType == model.TaskWebProbe {
			webProbe = append(webProbe, line)
		}
	}

	sort.Strings(allDomains)
	sort.Strings(resolved)
	sort.Strings(abnormal)
	sort.Strings(webProbe)
	sort.Strings(uniqueIPs)
	sort.Strings(cBlocks)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("子域名（%d）:\n", len(allDomains)))
	for _, s := range allDomains {
		b.WriteString(" - " + s + "\n")
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("IP（%d）:\n", len(resolved)))
	for _, s := range resolved {
		b.WriteString(" - " + s + "\n")
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("域名解析IP列表（%d）:\n", len(uniqueIPs)))
	for _, ip := range uniqueIPs {
		b.WriteString(" - " + ip + "\n")
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("域名解析IP归属/C段信息（%d）:\n", len(cBlocks)))
	for _, c := range cBlocks {
		country := joinSetOrDash(countriesByC[c], "/")
		region := joinSetOrDash(regionsByC[c], "/")
		operator := joinSetOrDash(operatorsByC[c], " / ")
		b.WriteString(fmt.Sprintf(" - C段=%s | 国家=%s | 地区=%s | 运营商=%s\n", c, country, region, operator))
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("未解析或解析内网IP域名（%d）:\n", len(abnormal)))
	for _, s := range abnormal {
		b.WriteString(" - " + s + "\n")
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("WEB指纹探测（%d）:\n", len(webProbe)))
	for _, s := range webProbe {
		b.WriteString(" - " + s + "\n")
	}
	return b.String()
}

func extractIPsFromResolvedLine(line string) []string {
	idx := strings.Index(line, "| IP=")
	if idx < 0 {
		return nil
	}
	rest := strings.TrimSpace(line[idx+len("| IP="):])
	end := strings.Index(rest, "|")
	if end >= 0 {
		rest = strings.TrimSpace(rest[:end])
	}
	if rest == "" || rest == "-" {
		return nil
	}
	parts := strings.Split(rest, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		ip := strings.TrimSpace(p)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func extractGeoInfoForIP(line string, ip string) string {
	key := "| IP=" + ip + " | "
	if strings.Contains(line, key) {
		parts := strings.SplitN(line, key, 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	idx := strings.Index(line, "| 国家=")
	if idx >= 0 {
		return strings.TrimSpace(line[idx+2:])
	}
	return ""
}

func parseGeoColumns(geo string) (country string, region string, operator string) {
	parts := strings.Split(geo, "|")
	for _, raw := range parts {
		item := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(item, "国家="):
			country = strings.TrimSpace(strings.TrimPrefix(item, "国家="))
		case strings.HasPrefix(item, "地区="):
			region = strings.TrimSpace(strings.TrimPrefix(item, "地区="))
		case strings.HasPrefix(item, "运营商="):
			operator = strings.TrimSpace(strings.TrimPrefix(item, "运营商="))
		}
	}
	return
}

func joinSetOrDash(m map[string]struct{}, sep string) string {
	if len(m) == 0 {
		return "-"
	}
	values := make([]string, 0, len(m))
	for v := range m {
		v = strings.TrimSpace(v)
		if v != "" {
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return "-"
	}
	sort.Strings(values)
	return strings.Join(values, sep)
}

func toIPv4CBlock(ip string) string {
	parts := strings.Split(strings.TrimSpace(ip), ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
}
