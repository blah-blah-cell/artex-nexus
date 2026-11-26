param(
    [ValidateSet("native", "docker")]
    [string]$Mode = "native",
    [switch]$SkipDb,
    [ValidateSet("", "antigravity", "claude", "cursor", "zcode", "freebuff", "artex")]
    [string]$Client = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function New-RandomHex([int]$ByteCount = 24) {
    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes) -replace "-", "").ToLowerInvariant()
}

function Ensure-EnvFile {
    $envPath = Join-Path $RepoRoot ".env"
    if (Test-Path $envPath) {
        Write-Host "[*] Keeping existing .env"
        return
    }
    Write-Host "[*] Creating .env from .env.example with generated secrets..."
    $text = Get-Content -Raw (Join-Path $RepoRoot ".env.example")
    $text = $text -replace "POSTGRES_PASSWORD=change-me-to-a-strong-password", ("POSTGRES_PASSWORD=" + (New-RandomHex 24))
    $text = $text -replace "MCP_AUTH_TOKEN=change-me-to-a-random-bearer-token", ("MCP_AUTH_TOKEN=" + (New-RandomHex 24))
    [System.IO.File]::WriteAllText($envPath, $text, [System.Text.UTF8Encoding]::new($false))
}

Push-Location $RepoRoot
try {
    New-Item -ItemType Directory -Force -Path "data", "data\receipts", "workspace" | Out-Null

    if ((Test-Path ".git") -and -not (Test-Path "vendor\ARTEX\go.mod")) {
        Write-Host "[*] Initializing vendor/ARTEX git submodule..."
        git submodule update --init --recursive
        if ($LASTEXITCODE -ne 0) { throw "git submodule update failed" }
    }

    Ensure-EnvFile

    if ($Mode -eq "docker") {
        if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
            throw "Missing required tool: docker"
        }
        $dbPath = Join-Path $RepoRoot "data\cve_kb_med_plus.sqlite"
        if (-not $SkipDb -and -not (Test-Path $dbPath)) {
            Write-Host "[*] Building nexus-sync image to fetch CVE DB into ./data..."
            docker compose build cve-intel-mcp
            if ($LASTEXITCODE -ne 0) { throw "docker compose build failed" }
            docker compose run --rm -v "${RepoRoot}\data:/data" cve-intel-mcp nexus-sync fetch --out /data/cve_kb_med_plus.sqlite
            if ($LASTEXITCODE -ne 0) { throw "docker DB fetch failed" }
        }
        Write-Host "[*] Starting Docker Compose stack..."
        docker compose up -d --build
        if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
        Write-Host "[+] Docker stack started. Check health with: docker compose ps"
        return
    }

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "Missing required tool: cargo (install Rust from https://rustup.rs)"
    }
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw "Missing required tool: go (install Go 1.26+ from https://go.dev/dl/)"
    }

    Write-Host "[*] Building Rust workspace (nexus-sync, cve-intel-mcp)..."
    cargo build --release --locked --workspace
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    Write-Host "[*] Building Go MCP servers..."
    New-Item -ItemType Directory -Force -Path "go\bin" | Out-Null
    Push-Location "go"
    try {
        $prevCgo = $env:CGO_ENABLED
        $env:CGO_ENABLED = "0"
        go build -trimpath -ldflags="-s -w" -o "bin\patch-diff-mcp.exe" ./cmd/patch-diff-mcp
        if ($LASTEXITCODE -ne 0) { throw "go build patch-diff-mcp failed" }
        go build -trimpath -ldflags="-s -w" -o "bin\scope-guard-mcp.exe" ./cmd/scope-guard-mcp
        if ($LASTEXITCODE -ne 0) { throw "go build scope-guard-mcp failed" }
        go build -trimpath -ldflags="-s -w" -o "bin\attack-surface-mcp.exe" ./cmd/attack-surface-mcp
        if ($LASTEXITCODE -ne 0) { throw "go build attack-surface-mcp failed" }
    } finally {
        if ($null -eq $prevCgo) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $prevCgo }
        Pop-Location
    }

    $syncBin = Join-Path $RepoRoot "target\release\nexus-sync.exe"
    if (-not $SkipDb) {
        Write-Host "[*] Fetching prebuilt Medium+ CVE/OSV SQLite database..."
        & $syncBin fetch --out (Join-Path $RepoRoot "data\cve_kb_med_plus.sqlite")
        if ($LASTEXITCODE -ne 0) { throw "nexus-sync fetch failed" }
        & $syncBin doctor --db (Join-Path $RepoRoot "data\cve_kb_med_plus.sqlite")
        if ($LASTEXITCODE -ne 0) { throw "nexus-sync doctor failed" }
    } else {
        Write-Host "[*] Skipping CVE DB fetch (-SkipDb). Run '.\target\release\nexus-sync.exe fetch' before querying."
    }

    if ($Client) {
        Write-Host ""
        Write-Host "[*] MCP client config ($Client):"
        & $syncBin init-mcp --client $Client --repo-root $RepoRoot
    }

    Write-Host ""
    Write-Host "[+] ARTEX-Nexus native install complete."
    Write-Host "    - Print MCP config:  .\target\release\nexus-sync.exe init-mcp --client claude"
    Write-Host "    - Local web console: .\target\release\nexus-sync.exe serve --host 127.0.0.1 --port 8088"
    Write-Host "    - Full setup guide:  SETUP.md"
} finally {
    Pop-Location
}
