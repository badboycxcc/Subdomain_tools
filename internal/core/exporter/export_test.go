package exporter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"subdomain-tools/internal/core/model"
)

func TestExportTXTAndJSON(t *testing.T) {
	tmp := t.TempDir()
	records := []model.Record{
		{
			Value:     "a.example.com",
			TaskType:  model.TaskSubdomain,
			Query:     "example.com",
			Sources:   []string{"crtsh"},
			FirstSeen: time.Now(),
		},
	}

	txtPath := filepath.Join(tmp, "a.txt")
	if err := Export(txtPath, records, FormatTXT); err != nil {
		t.Fatalf("export txt failed: %v", err)
	}
	txtData, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatalf("read txt failed: %v", err)
	}
	if strings.TrimSpace(string(txtData)) != "a.example.com" {
		t.Fatalf("unexpected txt content: %s", string(txtData))
	}

	jsonPath := filepath.Join(tmp, "a.json")
	if err := Export(jsonPath, records, FormatJSON); err != nil {
		t.Fatalf("export json failed: %v", err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read json failed: %v", err)
	}
	if !strings.Contains(string(jsonData), "\"value\": \"a.example.com\"") {
		t.Fatalf("unexpected json content: %s", string(jsonData))
	}
}
