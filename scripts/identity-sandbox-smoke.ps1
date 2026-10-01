[CmdletBinding()]
param(
    [string]$OutputPath = "identity-sandbox-evidence.json"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath "Cargo.toml")) {
    throw "Run this script from the repository root."
}

$checks = @(
    @{
        name = "oidc-local-idp"
        args = @("test", "-j1", "-p", "llm-firewall", "--lib", "local_idp", "--", "--nocapture")
    },
    @{
        name = "saml-local-signed-idp"
        args = @("test", "-j1", "-p", "llm-firewall", "--lib", "saml_auth::tests::local_signed_customer_idp_completes_sp_initiated_flow", "--", "--nocapture")
    },
    @{
        name = "scim-conformance-fixture"
        args = @("test", "-j1", "-p", "llm-firewall", "--test", "proxy_tenants", "scim_conformance_fixture_covers_supported_users_and_groups_subset", "--", "--nocapture")
    },
    @{
        name = "scim-loopback-http-sandbox"
        args = @("test", "-j1", "-p", "llm-firewall", "--test", "scim_network", "--", "--nocapture")
    }
)

$results = [System.Collections.Generic.List[object]]::new()
$failed = $false
foreach ($check in $checks) {
    $started = [DateTimeOffset]::UtcNow
    Write-Host "Running $($check.name)..."
    & cargo @($check.args)
    $exitCode = $LASTEXITCODE
    $results.Add([pscustomobject]@{
        name = $check.name
        command = "cargo $($check.args -join ' ')"
        started_at_utc = $started.ToString("O")
        finished_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
        exit_code = $exitCode
        status = if ($exitCode -eq 0) { "passed" } else { "failed" }
    })
    if ($exitCode -ne 0) {
        $failed = $true
        Write-Warning "$($check.name) failed with exit code $exitCode."
    }
}

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $resolvedOutput
if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}
[pscustomobject]@{
    schema_version = 1
    evidence = "local-or-sandbox-idp"
    generated_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
    repository = (Get-Location).Path
    checks = @($results)
    status = if ($failed) { "failed" } else { "passed" }
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resolvedOutput -Encoding utf8

if ($failed) {
    throw "One or more local identity checks failed. Evidence was written to $resolvedOutput."
}
Write-Host "Identity sandbox checks passed. Evidence: $resolvedOutput"
