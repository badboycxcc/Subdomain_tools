package collect

import (
	"strings"
	"time"

	"subdomain-tools/internal/core/model"
)

type Deduper struct {
	records map[string]model.Record
}

func NewDeduper() *Deduper {
	return &Deduper{records: make(map[string]model.Record)}
}

func (d *Deduper) Add(taskType model.TaskType, query, value, source string) (model.Record, bool) {
	key := normalizeKey(taskType, query, value)
	if key == "" {
		return model.Record{}, false
	}
	if old, ok := d.records[key]; ok {
		if !contains(old.Sources, source) {
			old.Sources = append(old.Sources, source)
			d.records[key] = old
		}
		return old, false
	}
	r := model.Record{
		Value:     normalizedValue(taskType, value),
		TaskType:  taskType,
		Query:     strings.ToLower(strings.TrimSpace(query)),
		Sources:   []string{source},
		FirstSeen: time.Now(),
	}
	d.records[key] = r
	return r, true
}

func (d *Deduper) Records() []model.Record {
	out := make([]model.Record, 0, len(d.records))
	for _, r := range d.records {
		out = append(out, r)
	}
	return out
}

func normalizeKey(taskType model.TaskType, query, value string) string {
	v := normalizedValue(taskType, value)
	if v == "" {
		return ""
	}
	if taskType == model.TaskReverseIP {
		return strings.ToLower(strings.TrimSpace(query)) + "|" + v
	}
	return v
}

func normalizedValue(taskType model.TaskType, v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "*.")
	v = strings.TrimSuffix(v, ".")
	if strings.ContainsAny(v, " \t/") {
		return ""
	}
	if taskType == model.TaskSubdomain {
		if strings.Count(v, ".") < 1 {
			return ""
		}
	}
	return v
}

func contains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}
