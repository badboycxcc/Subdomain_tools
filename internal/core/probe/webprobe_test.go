package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractHTMLTitle(t *testing.T) {
	body := []byte("<html><head><title> Hello  World </title></head><body>x</body></html>")
	if got := extractHTMLTitle(body); got != "Hello World" {
		t.Fatalf("unexpected title: %q", got)
	}
}

func TestProbeURL(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "unit-test")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>ProbeOK</title><script src=\"/vue.js\"></script>"))
	}))
	defer s.Close()

	p, err := NewProber(5 * time.Second)
	if err != nil {
		t.Fatalf("new prober failed: %v", err)
	}
	result := p.ProbeURL(context.Background(), s.URL)
	if result.Error != "" {
		t.Fatalf("probe failed: %s", result.Error)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", result.StatusCode)
	}
	if result.Title != "ProbeOK" {
		t.Fatalf("unexpected title: %q", result.Title)
	}
}
