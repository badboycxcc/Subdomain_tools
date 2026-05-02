# Subdomain Tools (MVP)

Golang + Fyne desktop tool for:

- Subdomain collection from public/offical APIs
- Reverse IP aggregation from multiple public sources
- Real-time GUI execution/cancel/log/result view
- Export as TXT / CSV / JSON

## Quick Start

```bash
go mod tidy
go run ./cmd/subdomain-tools
```

## Current Providers

### Subdomain

- `subfinder_sdk`:
  - Built-in SDK: `github.com/projectdiscovery/subfinder/v2/pkg/runner`
  - Note: no local `subfinder` binary required
- `ipthc_subdomain`:
  - API: `POST https://ip.thc.org/api/v1/lookup/subdomains`
  - JSON body: `{"domain":"example.com"}`
- `hackertarget_hostsearch_subdomain`:
  - API: `GET https://api.hackertarget.com/hostsearch/?q={domain}`
  - Parse line format: `host,ip` (take `host` only)
- `urlscan`:
  - API: `GET https://urlscan.io/api/v1/search/?q=domain:{domain}`
  - Extracted fields: `results[].task.domain` and `results[].page.domain`
- `myssl`:
  - API: `GET https://myssl.com/api/v1/discover_sub_domain?domain={domain}`
  - Extracted fields: `data[].domain`
- `rapiddns`:
  - API: `GET https://rapiddns.io/api/search/{domain}?page=1&pagesize=100&search_type=subdomain`
  - Auth header: `X-API-KEY: rdns_xxx`
  - Extracted fields: `data.data[].subdomain`
- `viewdns`:
  - API: `GET https://api.viewdns.info/subdomains/?domain={domain}&apikey={key}&page=1&output=json`
  - Extracted fields: `response.subdomains[].name` (and optional `ips[]`)

### Reverse IP

- `ipthc`:
  - API style used in MVP: `GET https://ip.thc.org/{ip}?l=100&noheader=1`
  - Fallback: `GET https://ip.thc.org/?ip={ip}`
- `hackertarget`:
  - API: `https://api.hackertarget.com/reverseiplookup/?q={ip}`
- `urlscan`:
  - API: `GET https://urlscan.io/api/v1/search/?q=ip:{ip}`
  - Extracted fields: `results[].task.domain` and `results[].page.domain`
- `rapiddns`:
  - API: `GET https://rapiddns.io/api/search/{ip}?page=1&pagesize=100&search_type=ip`
  - Auth header: `X-API-KEY: rdns_xxx`
  - Extracted fields: `data.data[].subdomain`
- `viewdns`:
  - API: `GET https://api.viewdns.info/reverseip/?host={ip}&apikey={key}&output=json`
  - Extracted fields: `response.domains[].name`

### Web Probe / Tech Detection

- HTTP probing: built-in lightweight prober module
- Technology detection: `github.com/projectdiscovery/wappalyzergo`
- Full pipeline button in GUI: collect subdomains -> resolve current/passive IPs -> abnormal host collision -> web probe

## GUI Tabs

- `Subdomains`: input root domain, start/cancel, real-time lines
- `Subdomains`: supports `开始全流程` (pipeline mode)
- `Reverse IP`: input IP, start/cancel task
- `Results`: filter + export
- `Settings`: RapidDNS API key, ViewDNS API key, DNS resolvers, hosts collision/web probe switches, timeout, concurrency, retries
- `Logs`: provider logs and errors

## Tests

```bash
go test ./...
```

Includes:

- provider parser tests (`testdata/providers`)
- dedup/source-merge tests
- exporter tests

## Cross Build (Windows host)

```powershell
./scripts/build-cross.ps1
```

Notes:

- Windows build works out-of-the-box.
- Linux/macOS GUI cross-build may require additional OpenGL/cgo toolchain on host.
