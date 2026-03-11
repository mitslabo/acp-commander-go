Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$outDir = Join-Path $repoRoot 'dist'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$targets = @(
    @{ GOOS = 'windows'; GOARCH = 'amd64'; Suffix = '.exe' },
    @{ GOOS = 'linux'; GOARCH = 'amd64'; Suffix = '' },
    @{ GOOS = 'linux'; GOARCH = 'arm64'; Suffix = '' },
    @{ GOOS = 'linux'; GOARCH = 'arm'; GOARM = '7'; Suffix = '' }
)

$oldCgoEnabled = $env:CGO_ENABLED
$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldGoarm = $env:GOARM

try {
    foreach ($target in $targets) {
        $env:CGO_ENABLED = '0'
        $env:GOOS = $target.GOOS
        $env:GOARCH = $target.GOARCH

        if ($target.ContainsKey('GOARM')) {
            $env:GOARM = $target.GOARM
        }
        else {
            Remove-Item Env:GOARM -ErrorAction SilentlyContinue
        }

        $name = "acp-commander_$($target.GOOS)_$($target.GOARCH)$($target.Suffix)"
        $outPath = Join-Path $outDir $name

        Write-Host "Building $name ..."
        go build -trimpath -tags "netgo,osusergo" -ldflags "-s -w -buildid=" -o $outPath ./cmd/acp-commander

        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $name"
        }
    }
}
finally {
    if ($null -eq $oldCgoEnabled) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $oldCgoEnabled }
    if ($null -eq $oldGoos) { Remove-Item Env:GOOS -ErrorAction SilentlyContinue } else { $env:GOOS = $oldGoos }
    if ($null -eq $oldGoarch) { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue } else { $env:GOARCH = $oldGoarch }
    if ($null -eq $oldGoarm) { Remove-Item Env:GOARM -ErrorAction SilentlyContinue } else { $env:GOARM = $oldGoarm }
}

Write-Host "Done. Artifacts are in: $outDir"
