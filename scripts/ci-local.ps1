# Run selected workspace and supply-chain checks locally.
#
# Runs formatting, locked default-feature Clippy and Rust tests, the documented
# cargo-audit exception, and the generated agent scorecard comparison. Requires
# Rust with rustfmt/clippy, Python on PATH, and cargo-audit for the default run.
# Dependency downloads and advisory database updates can use the network.
# Hosted CI also covers Python safety suites, optional features, native target
# matrices, service integrations, isolated binary acceptance and containers.
# Windows PowerShell 5.1 compatible; native command exit codes are checked.
#
#   pwsh scripts/ci-local.ps1            # all checks selected by this script
#   pwsh scripts/ci-local.ps1 -Quick     # fmt + clippy + test only

[CmdletBinding()]
param(
    [switch]$Quick,
    # Limit concurrent Cargo jobs to bound local CPU and memory use.
    # Adjust this value for the machine running the checks.
    [int]$Jobs = 4
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $Body
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL $Name (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host ("ok   {0} ({1:n0}s)" -f $Name, $sw.Elapsed.TotalSeconds) -ForegroundColor Green
}

Step 'cargo fmt --all -- --check' { cargo fmt --all -- --check }

# Clippy keeps its own target directory so its check-only artifacts never sit
# beside the test build's. Harmless, and it keeps the two caches independent.
Step "cargo clippy --locked --workspace --all-targets -j $Jobs -- -D warnings" {
    $saved = $env:CARGO_TARGET_DIR
    $env:CARGO_TARGET_DIR = Join-Path $root 'target\clippy'
    try {
        cargo clippy --locked --workspace --all-targets -j $Jobs -- -D warnings
    } finally {
        if ($null -eq $saved) { Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue }
        else { $env:CARGO_TARGET_DIR = $saved }
    }
}

Step "cargo test --locked --workspace -j $Jobs" { cargo test --locked --workspace -j $Jobs }

if ($Quick) {
    Write-Host ""
    Write-Host "Selected formatting, default-feature Clippy and Rust tests passed. Audit and scorecard checks skipped." -ForegroundColor Yellow
    exit 0
}

Step 'cargo audit' {
    cargo audit
}

Step 'agent scorecard byte-compare (benchmark.yml regression gate)' {
    $expected = Join-Path $root 'docs/benchmarks/agent-security-scorecard.generated.md'
    # cargo writes UTF-8; Windows PowerShell 5.1 would otherwise decode it as the
    # OEM code page and turn an em-dash into "тАФ". Read it as UTF-8, compare in
    # memory, and never round-trip through Out-File, which adds a BOM.
    $savedEnc = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    try {
        $lines = cargo run --locked -q --release -p soup-wall-bench -j $Jobs -- --agent crates/bench/corpora/agent_sessions.jsonl
    } finally {
        [Console]::OutputEncoding = $savedEnc
    }
    if ($LASTEXITCODE -ne 0) { return }
    $a = (($lines -join "`n") + "`n") -replace "`r`n", "`n"
    $e = ([System.IO.File]::ReadAllText($expected, [System.Text.Encoding]::UTF8)) -replace "`r`n", "`n"
    if ($a -ne $e) {
        Write-Host "generated scorecard differs from $expected" -ForegroundColor Red
        Write-Host "regenerate it deliberately if the corpus or policy changed; never edit it by hand"
        $global:LASTEXITCODE = 1
        return
    }
    $global:LASTEXITCODE = 0
}

Write-Host ""
Write-Host "Selected local formatting, default-feature Rust, advisory and agent scorecard checks passed." -ForegroundColor Green
