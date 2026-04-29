param(
  [string]$OutDir = "build"
)

$ErrorActionPreference = "Stop"

if (!(Test-Path $OutDir)) {
  New-Item -ItemType Directory -Path $OutDir | Out-Null
}

Write-Host "[*] Building windows/amd64"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o "$OutDir/subdomain-tools-windows-amd64.exe" ./cmd/subdomain-tools

Write-Host "[*] Building linux/amd64 (may require extra toolchain for Fyne/OpenGL)"
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o "$OutDir/subdomain-tools-linux-amd64" ./cmd/subdomain-tools

Write-Host "[*] Building darwin/amd64 (may require extra toolchain for Fyne/OpenGL)"
$env:GOOS = "darwin"
$env:GOARCH = "amd64"
go build -o "$OutDir/subdomain-tools-darwin-amd64" ./cmd/subdomain-tools

Write-Host "[+] Done"
