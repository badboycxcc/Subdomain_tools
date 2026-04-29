package reverseip

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePlainLines(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "providers", "reverseip", "ipthc.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read testdata failed: %v", err)
	}
	out := parsePlainLines(data)
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), out)
	}
}

func TestParseHackerTargetLines(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "providers", "reverseip", "hackertarget.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read testdata failed: %v", err)
	}
	out, err := parseHackerTargetLines(data)
	if err != nil {
		t.Fatalf("parse hackertarget failed: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), out)
	}
}

func TestParseURLScanReverseIPJSON(t *testing.T) {
	data := []byte(`{
		"results":[
			{"task":{"domain":"a.example.com"},"page":{"domain":"b.example.com"}},
			{"task":{"domain":"a.example.com"},"page":{"domain":"x.other.com"}},
			{"task":{"domain":"invalid"},"page":{"domain":""}}
		]
	}`)
	out, err := parseURLScanReverseIPJSON(data)
	if err != nil {
		t.Fatalf("parse urlscan reverse ip failed: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 records, got %d: %v", len(out), out)
	}
}
