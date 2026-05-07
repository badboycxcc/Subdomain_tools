package providers

import (
	"regexp"
	"strings"
)

var (
	sensitiveKVPattern = regexp.MustCompile(`(?i)("?(?:api[_-]?key|token|secret|password|authorization)"?\s*[:=]\s*"?)([^"\\,\s}{]{4,})`)
	longTokenPattern   = regexp.MustCompile(`\b[A-Za-z0-9_-]{24,}\b`)
)

// RedactedPreview returns a single-line sanitized preview of response body.
func RedactedPreview(body []byte, limit int) string {
	if limit <= 0 {
		limit = 300
	}
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "-"
	}

	s = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(s)
	s = strings.Join(strings.Fields(s), " ")

	s = sensitiveKVPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := sensitiveKVPattern.FindStringSubmatch(m)
		if len(sub) != 3 {
			return m
		}
		return sub[1] + redactToken(sub[2])
	})

	s = longTokenPattern.ReplaceAllStringFunc(s, redactToken)

	rs := []rune(s)
	if len(rs) > limit {
		return string(rs[:limit]) + "...(truncated)"
	}
	return s
}

func redactToken(v string) string {
	if len(v) <= 8 {
		return "***"
	}
	return v[:3] + "***" + v[len(v)-3:]
}
