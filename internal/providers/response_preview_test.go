package providers

import (
	"strings"
	"testing"
)

func TestRedactedPreview_MasksSensitiveFields(t *testing.T) {
	body := []byte(`{"msg":"failed","api_key":"abcdefghijklmnopqrstuvwxyz123456","token":"short1234"}`)
	out := RedactedPreview(body, 300)
	if strings.Contains(out, "abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatalf("expected api_key to be masked, got: %s", out)
	}
	if strings.Contains(out, "short1234") {
		t.Fatalf("expected token to be masked, got: %s", out)
	}
}

func TestRedactedPreview_TruncatesByRuneLength(t *testing.T) {
	body := []byte(`{"msg":"` + strings.Repeat("ab ", 220) + `"}`)
	out := RedactedPreview(body, 300)
	if !strings.HasSuffix(out, "...(truncated)") {
		t.Fatalf("expected truncated suffix, got: %s", out)
	}
}
