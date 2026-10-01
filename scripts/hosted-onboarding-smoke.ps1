[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl,

    [switch]$AllowHttpForLocal,

    [int]$TimeoutSeconds = 10
)

$ErrorActionPreference = "Stop"

if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 60) {
    throw "TimeoutSeconds must be between 1 and 60."
}

try {
    $base = [System.Uri]$BaseUrl
}
catch {
    throw "BaseUrl must be an absolute HTTP(S) URL."
}

if (-not $base.IsAbsoluteUri -or $base.UserInfo -or $base.Query -or $base.Fragment -or
    $base.Scheme -notin @("http", "https") -or [string]::IsNullOrWhiteSpace($base.Host)) {
    throw "BaseUrl must be an absolute HTTP(S) URL without credentials, query, or fragment."
}
if ($base.Scheme -ne "https" -and -not $AllowHttpForLocal) {
    throw "Hosted smoke checks require HTTPS. Use -AllowHttpForLocal only for loopback testing."
}
if ($base.Scheme -eq "http" -and $base.Host -notin @("127.0.0.1", "localhost", "::1")) {
    throw "-AllowHttpForLocal is restricted to a loopback host."
}

$root = $base.AbsoluteUri.TrimEnd('/')

function Invoke-Probe([string]$Path) {
    $uri = "$root$Path"
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $uri `
            -TimeoutSec $TimeoutSeconds -MaximumRedirection 0
        return [pscustomobject]@{
            Path = $Path
            StatusCode = [int]$response.StatusCode
            Body = [string]$response.Content
        }
    }
    catch [System.Net.WebException] {
        $response = $_.Exception.Response
        if ($null -ne $response) {
            return [pscustomobject]@{
                Path = $Path
                StatusCode = [int]$response.StatusCode
                Body = ""
            }
        }
        throw "Probe $Path failed: $($_.Exception.Message)"
    }
}

function Assert-JsonStatus($Probe, [string]$ExpectedStatus) {
    if ($Probe.StatusCode -ne 200) {
        throw "Probe $($Probe.Path) returned HTTP $($Probe.StatusCode); expected 200."
    }
    try {
        $document = $Probe.Body | ConvertFrom-Json
    }
    catch {
        throw "Probe $($Probe.Path) did not return a JSON health document."
    }
    if ($document.status -ne $ExpectedStatus) {
        throw "Probe $($Probe.Path) returned an unexpected health status."
    }
}

Write-Host "Checking hosted firewall health (no model request will be sent)..."
$liveness = Invoke-Probe "/healthz"
Assert-JsonStatus $liveness "live"
Write-Host "  /healthz: live"

$readiness = Invoke-Probe "/readyz"
Assert-JsonStatus $readiness "ready"
Write-Host "  /readyz: ready"

Write-Host "Hosted onboarding smoke check passed."
