package collect

import (
	"testing"

	"subdomain-tools/internal/core/model"
)

func TestDeduperMergeSources(t *testing.T) {
	d := NewDeduper()

	r1, isNew := d.Add(model.TaskSubdomain, "example.com", "WWW.Example.com", "crtsh")
	if !isNew {
		t.Fatalf("expected first record as new")
	}
	if r1.Value != "www.example.com" {
		t.Fatalf("unexpected normalized value: %s", r1.Value)
	}

	r2, isNew2 := d.Add(model.TaskSubdomain, "example.com", "www.example.com", "chaos")
	if isNew2 {
		t.Fatalf("expected duplicate record")
	}
	if len(r2.Sources) != 2 {
		t.Fatalf("expected merged sources, got %v", r2.Sources)
	}
}

func TestDeduperReverseIPKeyedByQuery(t *testing.T) {
	d := NewDeduper()
	_, isNew1 := d.Add(model.TaskReverseIP, "1.1.1.1", "a.example.com", "ipthc")
	_, isNew2 := d.Add(model.TaskReverseIP, "8.8.8.8", "a.example.com", "ipthc")
	if !isNew1 || !isNew2 {
		t.Fatalf("expected two unique records for same host on different IP")
	}
}
