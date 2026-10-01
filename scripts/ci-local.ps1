# Run the same gates GitHub Actions runs, on this machine, for free.
#
# Mirrors the `test` job of ci.yml, the cargo-audit job of supply-chain.yml
# (with its one documented exception), and the byte-for-byte agent scorecard
# comparison of benchmark.yml. Windows PowerShell 5.1 compatible: no `&&`,
# no `??`, exit codes checked after every native call.
#
#   pwsh scripts/ci-local.ps1            # everything
#   pwsh scripts/ci-local.ps1 -Quick     # fmt + clippy + test only
#
# A non-zero exit means CI would have failed on this commit.

[CmdletBinding()]
param(
    [switch]$Quick,
    # Build parallelism. Observed on this Windows machine, every time: a cold
    # full-workspace build at cargo's default parallelism fails with "can't find
    # crate for `llm_firewall`" / "crate `X` required to be available in rlib
    # format" -- test binaries get compiled before the freshly built .rlib files
    # are visible. Every run at -j 4 passed. Observed, not explained.
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
Step "cargo clippy --workspace --all-targets -j $Jobs -- -D warnings" {
    $saved = $env:CARGO_TARGET_DIR
    $env:CARGO_TARGET_DIR = Join-Path $root 'target\clippy'
    try {
        cargo clippy --workspace --all-targets -j $Jobs -- -D warnings
    } finally {
        if ($null -eq $saved) { Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue }
        else { $env:CARGO_TARGET_DIR = $saved }
    }
}

Step "cargo test --workspace -j $Jobs" { cargo test --workspace -j $Jobs }

if ($Quick) {
    Write-Host ""
    Write-Host "Quick gates passed. Skipped: cargo audit, agent scorecard byte-compare." -ForegroundColor Yellow
    exit 0
}

Step 'cargo audit --ignore RUSTSEC-2023-0071' {
    # Same single exception as supply-chain.yml: rsa Marvin via saml-rs's
    # optional XML-Enc path, which the product never configures a key for.
    cargo audit --ignore RUSTSEC-2023-0071
}

Step 'agent scorecard byte-compare (benchmark.yml regression gate)' {
    $expected = Join-Path $root 'docs/benchmarks/agent-security-scorecard.generated.md'
    # cargo writes UTF-8; Windows PowerShell 5.1 would otherwise decode it as the
    # OEM code page and turn an em-dash into "тАФ". Read it as UTF-8, compare in
    # memory, and never round-trip through Out-File, which adds a BOM.
    $savedEnc = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    try {
        $lines = cargo run -q --release -p soup-wall-bench -j $Jobs -- --agent crates/bench/corpora/agent_sessions.jsonl
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
Write-Host "All local CI gates passed." -ForegroundColor Green
