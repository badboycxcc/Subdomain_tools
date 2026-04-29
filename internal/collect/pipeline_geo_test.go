package collect

import "testing"

func TestFormatResolvedWithGeo(t *testing.T) {
	geo := map[string]ipGeoInfo{
		"1.1.1.1": {Country: "澳大利亚", Region: "昆士兰", Operator: "Cloudflare"},
	}
	got := formatResolvedWithGeo("a.example.com", []string{"1.1.1.1", "8.8.8.8"}, geo)
	want := "a.example.com | IP=1.1.1.1,8.8.8.8 | 国家=澳大利亚 | 地区=昆士兰 | 运营商=Cloudflare"
	if got != want {
		t.Fatalf("unexpected value: %s", got)
	}
}

func TestCompactParts(t *testing.T) {
	out := compactParts("A", "", " ", "B")
	if len(out) != 2 || out[0] != "A" || out[1] != "B" {
		t.Fatalf("unexpected compact result: %#v", out)
	}
}

func TestNormalizeGeoZh(t *testing.T) {
	got := normalizeGeoZh("Cambodia/Phnom Penh/Phnom Phen City")
	if got != "柬埔寨/金边/金边" {
		t.Fatalf("unexpected normalize result: %s", got)
	}
}
