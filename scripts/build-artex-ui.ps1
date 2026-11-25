param(
    [string]$TargetOS = "linux",
    [string]$TargetArch = "amd64",
    [string]$Output = ".\dist\artex-nexus-server"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not [System.IO.Path]::IsPathRooted($Output)) {
    $Output = Join-Path $RepoRoot $Output
}

$ArtexDir = Join-Path $RepoRoot "vendor\ARTEX"
$OverlaySrc = Join-Path $RepoRoot "ui-overlay\src"
$WebDir = Join-Path $ArtexDir "web"
$DistDir = Join-Path $ArtexDir "server\webui\dist"

$savedEnv = @{
    GOOS                    = $env:GOOS
    GOARCH                  = $env:GOARCH
    CGO_ENABLED             = $env:CGO_ENABLED
    NEXT_EXPORT             = $env:NEXT_EXPORT
    NEXT_TELEMETRY_DISABLED = $env:NEXT_TELEMETRY_DISABLED
}
$savedLoc = Get-Location

Write-Host "[*] Applying ARTEX-Nexus UI overlay into vendor/ARTEX/web/src..."
try {
    Copy-Item -Recurse -Force (Join-Path $OverlaySrc "*") (Join-Path $WebDir "src")

    Set-Location $WebDir
    if (-not (Test-Path "node_modules")) {
        npm ci --ignore-scripts
    }
    $env:NEXT_EXPORT = "1"
    $env:NEXT_TELEMETRY_DISABLED = "1"
    npx next build
    if ($LASTEXITCODE -ne 0) { throw "Next.js static export failed" }

    if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    Copy-Item -Recurse -Force (Join-Path $WebDir "out\*") $DistDir

    $OutParent = Split-Path -Parent $Output
    if ($OutParent) { New-Item -ItemType Directory -Force -Path $OutParent | Out-Null }

    Set-Location $ArtexDir
    $env:GOOS = $TargetOS
    $env:GOARCH = $TargetArch
    $env:CGO_ENABLED = "0"
    go build -tags embedui -trimpath -o $Output ./cmd/artex
    if ($LASTEXITCODE -ne 0) { throw "go build -tags embedui failed" }
    Write-Host "[+] Built ARTEX-Nexus UI-embedded binary: $Output"
}
finally {
    Set-Location $savedLoc
    foreach ($k in $savedEnv.Keys) {
        if ($null -eq $savedEnv[$k]) {
            Remove-Item -Path "Env:$k" -ErrorAction SilentlyContinue
        } else {
            Set-Item -Path "Env:$k" -Value $savedEnv[$k]
        }
    }
    Write-Host "[*] Restoring clean vendor/ARTEX git submodule working tree..."
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    git -C $ArtexDir checkout -- web/src/config/app-config.ts web/src/navigation/sidebar/sidebar-items.ts 2>$null | Out-Null
    $NexusPageDir = Join-Path $WebDir "src\app\(main)\nexus"
    if (Test-Path $NexusPageDir) { Remove-Item -Recurse -Force $NexusPageDir }
    if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
    git -C $ArtexDir checkout -- server/webui/dist 2>$null | Out-Null
    $ErrorActionPreference = $prevEap
}
