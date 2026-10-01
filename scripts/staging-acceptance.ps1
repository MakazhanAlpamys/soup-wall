[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl,

    [switch]$AllowHttpForLocal,

    [switch]$RequireRedis,

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
    throw "Staging acceptance requires HTTPS. Use -AllowHttpForLocal only for loopback testing."
}
if ($base.Scheme -eq "http" -and $base.Host -notin @("127.0.0.1", "localhost", "::1")) {
    throw "-AllowHttpForLocal is restricted to a loopback host."
}

$root = $base.AbsoluteUri.TrimEnd('/')

function Invoke-Get([string]$Path) {
    $uri = "$root$Path"
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $uri `
            -TimeoutSec $TimeoutSeconds -MaximumRedirection 0
        return [pscustomobject]@{
            Path = $Path
            StatusCode = [int]$response.StatusCode
            ContentType = [string]$response.Headers["Content-Type"]
            Body = [string]$response.Content
        }
    }
    catch [System.Net.WebException] {
        $response = $_.Exception.Response
        if ($null -ne $response) {
            $body = ""
            try {
                $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
                $body = $reader.ReadToEnd()
                $reader.Dispose()
            }
            catch {
                $body = ""
            }
            return [pscustomobject]@{
                Path = $Path
                StatusCode = [int]$response.StatusCode
                ContentType = [string]$response.Headers["Content-Type"]
                Body = $body
            }
        }
        throw "Probe $Path failed: $($_.Exception.Message)"
    }
}

function Assert-Health($Probe, [string]$ExpectedStatus) {
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

function Get-Gauge([string]$Body, [string]$Name) {
    $escaped = [regex]::Escape($Name)
    $match = [regex]::Match($Body, "(?m)^$escaped(?:\{[^}]*\})?\s+([0-9]+(?:\.[0-9]+)?)\s*$")
    if (-not $match.Success) {
        throw "Metrics response is missing gauge $Name."
    }
    return [double]$match.Groups[1].Value
}

$liveness = Invoke-Get "/healthz"
Assert-Health $liveness "live"

$readiness = Invoke-Get "/readyz"
Assert-Health $readiness "ready"

$metrics = Invoke-Get "/metrics"
if ($metrics.StatusCode -ne 200 -or $metrics.ContentType -notmatch "text/plain") {
    throw "Probe /metrics did not return the Prometheus text format."
}

# Metrics are intentionally aggregate-only. Fail if a deployment accidentally
# starts exporting tenant identifiers, URLs, credentials, or provider keys.
if ($metrics.Body -match "(?i)(tenant[_-]id|https?://|authorization|api[_-]?key|secret)" ) {
    throw "Metrics response contains a value that is not safe for the monitoring network."
}

$controlPlaneReady = Get-Gauge $metrics.Body "llm_firewall_control_plane_ready"
$auditQueueFailed = Get-Gauge $metrics.Body "llm_firewall_audit_queue_failed_events"
$usageFailed = Get-Gauge $metrics.Body "llm_firewall_usage_ledger_failed_events"
$redisEnabled = Get-Gauge $metrics.Body "llm_firewall_redis_limits_enabled"
$redisReady = Get-Gauge $metrics.Body "llm_firewall_redis_limits_ready"

if ($controlPlaneReady -ne 1) {
    throw "Control plane is not ready according to /metrics."
}
if ($auditQueueFailed -ne 0 -or $usageFailed -ne 0) {
    throw "Evidence persistence has recorded failures; do not accept this staging deployment."
}
if ($RequireRedis -and ($redisEnabled -ne 1 -or $redisReady -ne 1)) {
    throw "Redis is required but the shared limits backend is not ready."
}
if (-not $RequireRedis -and $redisReady -ne 1) {
    throw "Redis limits are not ready (or the configured fail-closed dependency is unavailable)."
}

[pscustomobject]@{
    acceptance = "passed"
    base_url_host = $base.Host
    healthz = $liveness.StatusCode
    readyz = $readiness.StatusCode
    control_plane_ready = [int]$controlPlaneReady
    audit_queue_failed_events = [int]$auditQueueFailed
    usage_ledger_failed_events = [int]$usageFailed
    redis_limits_enabled = [int]$redisEnabled
    redis_limits_ready = [int]$redisReady
    model_requests_sent = 0
} | ConvertTo-Json -Compress
