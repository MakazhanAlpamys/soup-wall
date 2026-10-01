[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Baseline", "PostgresDown", "RedisDown", "Recovered")]
    [string]$Phase,

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
    throw "Production dependency drills require HTTPS. Use -AllowHttpForLocal only for loopback testing."
}
if ($base.Scheme -eq "http" -and $base.Host -notin @("127.0.0.1", "localhost", "::1")) {
    throw "-AllowHttpForLocal is restricted to a loopback host."
}

$root = $base.AbsoluteUri.TrimEnd('/')

function Invoke-Probe([string]$Path) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Method Get -Uri "$root$Path" `
            -TimeoutSec $TimeoutSeconds -MaximumRedirection 0
        return [pscustomobject]@{
            Path = $Path
            StatusCode = [int]$response.StatusCode
            Body = [string]$response.Content
        }
    }
    catch {
        $response = $_.Exception.Response
        if ($null -ne $response -and $null -ne $response.StatusCode) {
            return [pscustomobject]@{
                Path = $Path
                StatusCode = [int]$response.StatusCode
                Body = ""
            }
        }
        throw "Probe $Path failed without an HTTP response."
    }
}

function Assert-Status($Probe, [int]$ExpectedStatus) {
    if ($Probe.StatusCode -ne $ExpectedStatus) {
        throw "Probe $($Probe.Path) returned HTTP $($Probe.StatusCode); expected $ExpectedStatus."
    }
}

function Assert-Liveness($Probe) {
    Assert-Status $Probe 200
    try {
        $document = $Probe.Body | ConvertFrom-Json
    }
    catch {
        throw "Probe /healthz did not return a JSON health document."
    }
    if ($document.status -ne "live") {
        throw "Probe /healthz returned an unexpected health status."
    }
}

function Get-Metric([string]$Body, [string]$Name) {
    $pattern = "(?m)^" + [regex]::Escape($Name) + "\s+([0-9]+(?:\.[0-9]+)?)\s*$"
    $match = [regex]::Match($Body, $pattern)
    if (-not $match.Success) {
        throw "Metric $Name was not present in the Prometheus response."
    }
    return [double]::Parse($match.Groups[1].Value, [System.Globalization.CultureInfo]::InvariantCulture)
}

$health = Invoke-Probe "/healthz"
Assert-Liveness $health
$readiness = Invoke-Probe "/readyz"
$metrics = Invoke-Probe "/metrics"
Assert-Status $metrics 200

$controlPlaneReady = Get-Metric $metrics.Body "llm_firewall_control_plane_ready"
$auditQueueEnabled = Get-Metric $metrics.Body "llm_firewall_audit_queue_enabled"
$redisEnabled = Get-Metric $metrics.Body "llm_firewall_redis_limits_enabled"
$redisReady = Get-Metric $metrics.Body "llm_firewall_redis_limits_ready"

switch ($Phase) {
    "Baseline" {
        Assert-Status $readiness 200
        if ($controlPlaneReady -ne 1 -or $auditQueueEnabled -ne 1 -or
            $redisEnabled -ne 1 -or $redisReady -ne 1) {
            throw "Baseline requires ready PostgreSQL, audit queue, and Redis limits."
        }
    }
    "PostgresDown" {
        Assert-Status $readiness 503
        if ($controlPlaneReady -ne 0) {
            throw "PostgresDown requires llm_firewall_control_plane_ready to be 0."
        }
    }
    "RedisDown" {
        Assert-Status $readiness 503
        if ($controlPlaneReady -ne 1 -or $redisEnabled -ne 1 -or $redisReady -ne 0) {
            throw "RedisDown requires an isolated Redis failure with a ready control plane."
        }
    }
    "Recovered" {
        Assert-Status $readiness 200
        if ($controlPlaneReady -ne 1 -or $auditQueueEnabled -ne 1 -or
            $redisEnabled -ne 1 -or $redisReady -ne 1) {
            throw "Recovered requires ready PostgreSQL, audit queue, and Redis limits."
        }
    }
}

[pscustomobject]@{
    phase = $Phase
    observed_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
    health_http_status = $health.StatusCode
    readiness_http_status = $readiness.StatusCode
    control_plane_ready = [int]$controlPlaneReady
    audit_queue_enabled = [int]$auditQueueEnabled
    redis_limits_enabled = [int]$redisEnabled
    redis_limits_ready = [int]$redisReady
} | ConvertTo-Json -Compress
