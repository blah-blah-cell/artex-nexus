param(
    [string]$TargetOS = "linux",
    [string]$TargetArch = "amd64",
    [string]$Output = "$env:TEMP\artex-linux-bin\artex"
)
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$ArtexDir = Join-Path $RepoRoot "vendor\ARTEX"
$OverlaySrc = Join-Path $RepoRoot "ui-overlay\src"
$WebDir = Join-Path $ArtexDir "web"
$DistDir = Join-Path $ArtexDir "server\webui\dist"

Write-Host "[*] Applying ARTEX-Nexus UI overlay into vendor/ARTEX/web/src..."
Copy-Item -Recurse -Force "$OverlaySrc\*" (Join-Path $WebDir "src")

try {
    Push-Location $WebDir
    if (-not (Test-Path "node_modules")) {
        npm ci --ignore-scripts
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
    }
    $env:NEXT_EXPORT = "1"
    $env:NEXT_TELEMETRY_DISABLED = "1"
    npx next build
    if ($LASTEXITCODE -ne 0) { throw "next build failed" }
    Pop-Location

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    Copy-Item -Recurse -Force (Join-Path $WebDir "out\*") $DistDir

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Output) | Out-Null
    Push-Location $ArtexDir
    $env:GOOS = $TargetOS
    $env:GOARCH = $TargetArch
    $env:CGO_ENABLED = "0"
    go build -tags embedui -trimpath -o $Output ./cmd/artex
    if ($LASTEXITCODE -ne 0) { throw "go build artex failed" }
    Pop-Location
    Write-Host "[+] Built ARTEX-Nexus UI-embedded binary: $Output"
} finally {
    Write-Host "[*] Restoring clean vendor/ARTEX git submodule working tree..."
    git -C $ArtexDir checkout -- web/src/config/app-config.ts web/src/navigation/sidebar/sidebar-items.ts 2>$null | Out-Null
    Remove-Item -Recurse -Force (Join-Path $WebDir "src\app\(main)\nexus") -ErrorAction SilentlyContinue
}
