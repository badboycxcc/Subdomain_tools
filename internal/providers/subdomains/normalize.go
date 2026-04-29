package subdomains

import "strings"

func NormalizeForReverseIP(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if idx := strings.IndexAny(s, "/ \t,;"); idx >= 0 {
		s = s[:idx]
	}
	if strings.Count(s, ".") < 1 {
		return ""
	}
	return s
}
