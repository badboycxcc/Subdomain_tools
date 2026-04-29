package store

import (
	"strings"
	"sync"

	"subdomain-tools/internal/core/model"
)

type MemoryStore struct {
	mu      sync.RWMutex
	records []model.Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make([]model.Record, 0, 128)}
}

func (m *MemoryStore) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = m.records[:0]
}

func (m *MemoryStore) AddBatch(records []model.Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, records...)
}

func (m *MemoryStore) All() []model.Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.Record, len(m.records))
	copy(out, m.records)
	return out
}

func (m *MemoryStore) FilterContains(keyword string) []model.Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	if keyword == "" {
		out := make([]model.Record, len(m.records))
		copy(out, m.records)
		return out
	}
	out := make([]model.Record, 0, len(m.records))
	for _, r := range m.records {
		if strings.Contains(strings.ToLower(r.Value), keyword) {
			out = append(out, r)
		}
	}
	return out
}
