package subdomains

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCRTShJSON(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "providers", "subdomains", "crtsh.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read testdata failed: %v", err)
	}
	out, err := parseCRTShJSON(data, "example.com")
	if err != nil {
		t.Fatalf("parse crtsh failed: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 records, got %d: %v", len(out), out)
	}
}

func TestParseChaosJSON(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "providers", "subdomains", "chaos.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read testdata failed: %v", err)
	}
	out, err := parseChaosJSON(data, "example.com")
	if err != nil {
		t.Fatalf("parse chaos failed: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 records, got %d: %v", len(out), out)
	}
	if out[0] != "www.example.com" {
		t.Fatalf("unexpected first host: %s", out[0])
	}
}

func TestParseIPTHCSubdomainJSON(t *testing.T) {
	data := []byte(`{"domains":[{"domain":"www.example.com"},{"domain":"other.test"},{"domain":"*.api.example.com"}]}`)
	out, err := parseIPTHCSubdomainJSON(data, "example.com")
	if err != nil {
		t.Fatalf("parse ipthc subdomain failed: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), out)
	}
}

func TestParseURLScanJSON(t *testing.T) {
	data := []byte(`{
		"results":[
			{"task":{"domain":"a.example.com"},"page":{"domain":"b.example.com","ip":"3.3.3.3"}},
			{"task":{"domain":"x.other.com"},"page":{"domain":"example.com","ip":"4.4.4.4"}}
		]
	}`)
	out, err := parseURLScanJSON(data, "example.com")
	if err != nil {
		t.Fatalf("parse urlscan failed: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 records, got %d: %v", len(out), out)
	}
	records, err := parseURLScanJSONRecords(data, "example.com")
	if err != nil || len(records) != 3 || records[0].IP == "" {
		t.Fatalf("expected urlscan ip records, got err=%v data=%+v", err, records)
	}
}

func TestParseMySSLJSON(t *testing.T) {
	data := []byte(`{
		"code":0,
		"data":[
			{"domain":"grow.example.com","ip":"5.5.5.5"},
			{"domain":"api.example.com","ip":"6.6.6.6"},
			{"domain":"xx.other.com"}
		]
	}`)
	out, err := parseMySSLJSON(data, "example.com")
	if err != nil {
		t.Fatalf("parse myssl failed: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), out)
	}
	records, err := parseMySSLJSONRecords(data, "example.com")
	if err != nil || len(records) != 2 || records[0].IP == "" {
		t.Fatalf("expected myssl ip records, got err=%v data=%+v", err, records)
	}
}

func TestParseHackerTargetHostSearchLines(t *testing.T) {
	data := []byte("www.example.com,1.1.1.1\napi.example.com,8.8.8.8\nx.other.com,9.9.9.9\n")
	out := parseHackerTargetHostSearchLines(data, "example.com")
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), out)
	}
	records := parseHackerTargetHostSearchRecords(data, "example.com")
	if len(records) != 2 || records[0].IP == "" {
		t.Fatalf("expected ip in records, got: %+v", records)
	}
}

func TestParseRapidDNSJSON(t *testing.T) {
	data := []byte(`{
		"status":200,
		"msg":"ok",
		"data":{
			"total":3,
			"status":"ok",
			"data":[
				{"subdomain":"a.example.com","value":"1.1.1.1"},
				{"subdomain":"example.com","value":"2.2.2.2"},
				{"subdomain":"x.other.com"}
			]
		}
	}`)
	out, total, err := parseRapidDNSJSON(data, "example.com")
	if err != nil {
		t.Fatalf("parse rapiddns failed: %v", err)
	}
	if total != 3 {
		t.Fatalf("unexpected total: %d", total)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), out)
	}
	records, _, err := parseRapidDNSJSONRecords(data, "example.com")
	if err != nil || len(records) != 2 || records[0].IP == "" {
		t.Fatalf("expected rapiddns ip records, got err=%v data=%+v", err, records)
	}
}

func TestParseViewDNSSubdomainsJSONRecords(t *testing.T) {
	data := []byte(`{
		"query":{"tool":"subdomains_PRO","domain":"example.com"},
		"response":{
			"subdomain_count":"3",
			"total_pages":"1",
			"current_page":"1",
			"subdomains":[
				{"name":"www.example.com","ips":["1.1.1.1"],"last_resolved":"2025-01-01"},
				{"name":"api.example.com","ips":[],"last_resolved":null},
				{"name":"x.other.com","ips":["2.2.2.2"],"last_resolved":"2025-01-01"}
			]
		}
	}`)
	records, totalPages, err := parseViewDNSSubdomainsJSONRecords(data, "example.com")
	if err != nil {
		t.Fatalf("parse viewdns subdomains failed: %v", err)
	}
	if totalPages != 1 {
		t.Fatalf("expected total_pages=1, got %d", totalPages)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d: %+v", len(records), records)
	}
	if records[0].IP != "1.1.1.1" {
		t.Fatalf("expected first ip=1.1.1.1, got %s", records[0].IP)
	}
}
