package domainips

import "testing"

func TestParseHostSearch(t *testing.T) {
	body := []byte("a.example.com,1.1.1.1\nb.example.com,2.2.2.2\na.example.com,1.1.1.1\n")
	got := parseHostSearch(body)
	if len(got) != 2 {
		t.Fatalf("unexpected host size: %d", len(got))
	}
	if len(got["a.example.com"]) != 1 || got["a.example.com"][0] != "1.1.1.1" {
		t.Fatalf("unexpected a.example.com mapping: %#v", got["a.example.com"])
	}
}
