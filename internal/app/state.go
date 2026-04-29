package app

import (
	"context"
	"sync"

	"subdomain-tools/internal/core/model"
	"subdomain-tools/internal/core/store"
)

type State struct {
	mu sync.RWMutex

	Running       bool
	CurrentTask   model.TaskType
	CurrentQuery  string
	Cancel        context.CancelFunc
	RawCount      int
	UniqueCount   int
	LastError     string
	ProviderState map[string]model.ProviderStatus
	Logs          []model.LogEntry
	Store         *store.MemoryStore
}

func NewState(memStore *store.MemoryStore) *State {
	return &State{
		ProviderState: make(map[string]model.ProviderStatus),
		Logs:          make([]model.LogEntry, 0, 128),
		Store:         memStore,
	}
}

func (s *State) AppendLog(entry model.LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Logs = append(s.Logs, entry)
	if len(s.Logs) > 2000 {
		s.Logs = s.Logs[len(s.Logs)-2000:]
	}
}

func (s *State) SnapshotLogs() []model.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.LogEntry, len(s.Logs))
	copy(out, s.Logs)
	return out
}
