package probe

import "testing"

func TestEnsureDNSPort(t *testing.T) {
	if got := ensureDNSPort("8.8.8.8"); got != "8.8.8.8:53" {
		t.Fatalf("unexpected resolver: %s", got)
	}
	if got := ensureDNSPort("1.1.1.1:5353"); got != "1.1.1.1:5353" {
		t.Fatalf("unexpected resolver keep port: %s", got)
	}
}

func TestShuffledResolvers(t *testing.T) {
	in := []string{"1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53"}
	out := shuffledResolvers(in)
	if len(out) != len(in) {
		t.Fatalf("unexpected len: %d", len(out))
	}
	seen := map[string]bool{}
	for _, r := range out {
		seen[r] = true
	}
	for _, r := range in {
		if !seen[r] {
			t.Fatalf("missing resolver: %s", r)
		}
	}
}

func TestNormalizeResolvers(t *testing.T) {
	out := normalizeResolvers([]string{"8.8.8.8", "8.8.8.8:53", " ", "1.1.1.1:5353"})
	if len(out) != 2 {
		t.Fatalf("unexpected resolvers: %v", out)
	}
	if out[0] != "8.8.8.8:53" || out[1] != "1.1.1.1:5353" {
		t.Fatalf("unexpected normalized result: %v", out)
	}
}
