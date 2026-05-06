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

func TestParseViewDNSReverseIPJSON(t *testing.T) {
	data := []byte(`{
		"query":{"tool":"reverseip_PRO","host":"8.8.8.8"},
		"response":{
			"domain_count":"3",
			"domains":[
				{"name":"a.example.com","last_resolved":"2024-09-25"},
				{"name":"a.example.com","last_resolved":"2024-09-26"},
				{"name":"x.other.com","last_resolved":"2024-09-27"}
			]
		}
	}`)
	out, err := parseViewDNSReverseIPJSON(data)
	if err != nil {
		t.Fatalf("parse viewdns reverseip failed: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), out)
	}
}

func TestParseRapidDNSReverseIPJSON(t *testing.T) {
	data := []byte(`{
		"status":200,
		"msg":"ok",
		"data":{
			"total":"3",
			"status":"ok",
			"data":[
				{"subdomain":"a.example.com"},
				{"subdomain":"a.example.com"},
				{"subdomain":"x.other.com"}
			]
		}
	}`)
	out, total, err := parseRapidDNSReverseIPJSON(data)
	if err != nil {
		t.Fatalf("parse rapiddns reverse ip failed: %v", err)
	}
	if total != 3 {
		t.Fatalf("expected total=3, got %d", total)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), out)
	}
}

func TestParseRapidDNSReverseIPJSON_DataStringError(t *testing.T) {
	data := []byte(`{"status":403,"msg":"forbidden","data":"invalid api key"}`)
	_, _, err := parseRapidDNSReverseIPJSON(data)
	if err == nil {
		t.Fatalf("expected error when rapiddns data is string")
	}
}
