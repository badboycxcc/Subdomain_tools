package exporter

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"subdomain-tools/internal/core/model"
)

type Format string

const (
	FormatTXT  Format = "txt"
	FormatCSV  Format = "csv"
	FormatJSON Format = "json"
)

func Export(path string, records []model.Record, format Format) error {
	switch format {
	case FormatTXT:
		return exportTXT(path, records)
	case FormatCSV:
		return exportCSV(path, records)
	case FormatJSON:
		return exportJSON(path, records)
	default:
		return exportTXT(path, records)
	}
}

func exportTXT(path string, records []model.Record) error {
	var b strings.Builder
	for _, r := range records {
		b.WriteString(r.Value)
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func exportCSV(path string, records []model.Record) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"value", "task_type", "query", "sources", "first_seen"}); err != nil {
		return err
	}
	for _, r := range records {
		row := []string{
			r.Value,
			string(r.TaskType),
			r.Query,
			strings.Join(r.Sources, "|"),
			r.FirstSeen.Format(time.RFC3339),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

func exportJSON(path string, records []model.Record) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func BuildExportPath(dir string, format Format) string {
	ts := time.Now().Format("20060102_150405")
	return filepath.Join(dir, "subdomain_tools_export_"+ts+"."+string(format))
}
