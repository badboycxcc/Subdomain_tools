package collect

import (
	"context"
	"fmt"
	"sync"
	"time"

	"subdomain-tools/internal/core/model"
	"subdomain-tools/internal/providers"
)

type EventType string

const (
	EventLog          EventType = "log"
	EventProviderDone EventType = "provider_done"
	EventRecord       EventType = "record"
	EventTaskDone     EventType = "task_done"
)

type Event struct {
	Type      EventType
	Time      time.Time
	Message   string
	Provider  string
	Record    model.Record
	IP        string
	IsNew     bool
	TaskType  model.TaskType
	RawCount  int
	UniqueCnt int
	Err       error
}

type Orchestrator struct {
	maxConcurrency int
}

func NewOrchestrator(maxConcurrency int) *Orchestrator {
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}
	return &Orchestrator{maxConcurrency: maxConcurrency}
}

func (o *Orchestrator) RunSubdomainTask(
	ctx context.Context,
	domain string,
	ps []providers.SubdomainProvider,
) <-chan Event {
	events := make(chan Event, 256)
	go func() {
		defer close(events)
		o.runSubdomain(ctx, domain, ps, events)
	}()
	return events
}

func (o *Orchestrator) RunReverseIPTask(
	ctx context.Context,
	ip string,
	ps []providers.ReverseIPProvider,
) <-chan Event {
	events := make(chan Event, 256)
	go func() {
		defer close(events)
		o.runReverseIP(ctx, ip, ps, events)
	}()
	return events
}

func (o *Orchestrator) runSubdomain(
	ctx context.Context,
	domain string,
	ps []providers.SubdomainProvider,
	events chan<- Event,
) {
	deduper := NewDeduper()
	rawCount := 0
	var mu sync.Mutex
	sem := make(chan struct{}, o.maxConcurrency)
	var wg sync.WaitGroup

	for _, provider := range ps {
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

			var values []providers.SubdomainRecord
			if rp, ok := p.(providers.SubdomainRecordProvider); ok {
				rs, err := rp.CollectSubdomainRecords(ctx, domain)
				if err != nil {
					events <- Event{
						Type:      EventProviderDone,
						Time:      time.Now(),
						Provider:  p.Name(),
						TaskType:  model.TaskSubdomain,
						Message:   fmt.Sprintf("%s 查询失败: %v", p.Name(), err),
						Err:       err,
						RawCount:  rawCount,
						UniqueCnt: len(deduper.Records()),
					}
					return
				}
				values = rs
			} else {
				result, err := p.CollectSubdomains(ctx, domain)
				if err != nil {
					events <- Event{
						Type:      EventProviderDone,
						Time:      time.Now(),
						Provider:  p.Name(),
						TaskType:  model.TaskSubdomain,
						Message:   fmt.Sprintf("%s 查询失败: %v", p.Name(), err),
						Err:       err,
						RawCount:  rawCount,
						UniqueCnt: len(deduper.Records()),
					}
					return
				}
				values = make([]providers.SubdomainRecord, 0, len(result))
				for _, host := range result {
					values = append(values, providers.SubdomainRecord{Host: host})
				}
			}

			providerRaw := 0
			providerNew := 0
			for _, item := range values {
				value := item.Host
				mu.Lock()
				providerRaw++
				rawCount++
				r, isNew := deduper.Add(model.TaskSubdomain, domain, value, p.Name())
				uniqueCnt := len(deduper.Records())
				if isNew {
					providerNew++
				}
				mu.Unlock()
				events <- Event{
					Type:      EventRecord,
					Time:      time.Now(),
					Provider:  p.Name(),
					TaskType:  model.TaskSubdomain,
					Record:    r,
					IP:        item.IP,
					IsNew:     isNew,
					RawCount:  rawCount,
					UniqueCnt: uniqueCnt,
				}
			}
			events <- Event{
				Type:      EventProviderDone,
				Time:      time.Now(),
				Provider:  p.Name(),
				TaskType:  model.TaskSubdomain,
				Message:   fmt.Sprintf("%s 子域名获取 %d 条，新增 %d 条，累计去重 %d 条", p.Name(), providerRaw, providerNew, len(deduper.Records())),
				RawCount:  rawCount,
				UniqueCnt: len(deduper.Records()),
			}
		}()
	}
	wg.Wait()
	events <- Event{
		Type:      EventTaskDone,
		Time:      time.Now(),
		TaskType:  model.TaskSubdomain,
		RawCount:  rawCount,
		UniqueCnt: len(deduper.Records()),
		Message:   fmt.Sprintf("子域名任务完成：原始 %d 条，去重 %d 条", rawCount, len(deduper.Records())),
	}
}

func (o *Orchestrator) runReverseIP(
	ctx context.Context,
	ip string,
	ps []providers.ReverseIPProvider,
	events chan<- Event,
) {
	deduper := NewDeduper()
	rawCount := 0
	var mu sync.Mutex
	sem := make(chan struct{}, o.maxConcurrency)
	var wg sync.WaitGroup

	for _, provider := range ps {
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

			result, err := p.CollectDomainsByIP(ctx, ip)
			if err != nil {
				events <- Event{
					Type:      EventProviderDone,
					Time:      time.Now(),
					Provider:  p.Name(),
					TaskType:  model.TaskReverseIP,
					Message:   fmt.Sprintf("%s 反查失败: %v", p.Name(), err),
					Err:       err,
					RawCount:  rawCount,
					UniqueCnt: len(deduper.Records()),
				}
				return
			}

			providerRaw := 0
			providerNew := 0
			for _, value := range result {
				mu.Lock()
				providerRaw++
				rawCount++
				r, isNew := deduper.Add(model.TaskReverseIP, ip, value, p.Name())
				uniqueCnt := len(deduper.Records())
				if isNew {
					providerNew++
				}
				mu.Unlock()
				events <- Event{
					Type:      EventRecord,
					Time:      time.Now(),
					Provider:  p.Name(),
					TaskType:  model.TaskReverseIP,
					Record:    r,
					IsNew:     isNew,
					RawCount:  rawCount,
					UniqueCnt: uniqueCnt,
				}
			}
			events <- Event{
				Type:      EventProviderDone,
				Time:      time.Now(),
				Provider:  p.Name(),
				TaskType:  model.TaskReverseIP,
				Message:   fmt.Sprintf("%s 反查域名 %d 条，新增 %d 条，累计去重 %d 条", p.Name(), providerRaw, providerNew, len(deduper.Records())),
				RawCount:  rawCount,
				UniqueCnt: len(deduper.Records()),
			}
		}()
	}
	wg.Wait()
	events <- Event{
		Type:      EventTaskDone,
		Time:      time.Now(),
		TaskType:  model.TaskReverseIP,
		RawCount:  rawCount,
		UniqueCnt: len(deduper.Records()),
		Message:   fmt.Sprintf("反查任务完成：原始 %d 条，去重 %d 条", rawCount, len(deduper.Records())),
	}
}
