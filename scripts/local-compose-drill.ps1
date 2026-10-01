[CmdletBinding()]
param(
    [string]$ComposeFile = "deploy/docker-compose.production.yaml",

    [string]$BaseUrl = "http://127.0.0.1:8080",

    [int]$TimeoutSeconds = 15
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ComposeFile -PathType Leaf)) {
    throw "ComposeFile was not found: $ComposeFile"
}
if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 60) {
    throw "TimeoutSeconds must be between 1 and 60."
}

try {
    $base = [System.Uri]$BaseUrl
}
catch {
    throw "BaseUrl must be an absolute loopback HTTP URL."
}
if (-not $base.IsAbsoluteUri -or $base.Scheme -ne "http" -or
    $base.Host -notin @("127.0.0.1", "localhost", "::1") -or
    $base.UserInfo -or $base.Query -or $base.Fragment) {
    throw "BaseUrl must be an absolute loopback HTTP URL without credentials, query, or fragment."
}

$composeArgs = @("-f", $ComposeFile)

function Invoke-Compose([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments) {
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        # Compose writes its human-readable progress to stderr. Capture it without
        # turning a successful `stop`/`start` progress line into a terminating PS error.
        $ErrorActionPreference = "Continue"
        $output = @(& docker compose @composeArgs @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($exitCode -ne 0) {
        $detail = ($output -join "`n").Trim()
        if ($detail.Length -gt 1000) {
            $detail = $detail.Substring(0, 1000)
        }
        throw "docker compose $($Arguments -join ' ') failed with exit code $exitCode. $detail"
    }
}

function Wait-Healthy([string]$Service) {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
    do {
        $containerId = ((& docker compose @composeArgs ps -q $Service 2>$null | Out-String).Trim())
        if ($containerId -match "\r?\n") {
            $containerId = ($containerId -split "\r?\n")[0].Trim()
        }
        if ($containerId) {
            $health = (& docker inspect --format '{{.State.Health.Status}}' $containerId 2>$null).Trim()
            if ($health -eq "healthy") {
                return
            }
            $state = (& docker inspect --format '{{.State.Status}}' $containerId 2>$null).Trim()
            if ($state -eq "exited" -or $state -eq "dead") {
                throw "$Service container entered terminal state '$state'."
            }
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "$Service did not become healthy within 120 seconds."
}

function Invoke-Phase([string]$Phase) {
    $output = & .\scripts\dependency-failure-drill.ps1 `
        -BaseUrl $BaseUrl `
        -Phase $Phase `
        -AllowHttpForLocal `
        -TimeoutSeconds $TimeoutSeconds
    return ($output -join "`n") | ConvertFrom-Json
}

$results = [System.Collections.Generic.List[object]]::new()
$cleanupError = $null
$operationError = $null
try {
    $acceptance = & .\scripts\staging-acceptance.ps1 `
        -BaseUrl $BaseUrl `
        -AllowHttpForLocal `
        -RequireRedis `
        -TimeoutSeconds $TimeoutSeconds
    $results.Add([pscustomobject]@{ phase = "BaselineAcceptance"; result = (($acceptance -join "`n") | ConvertFrom-Json) })

    Invoke-Compose stop postgres
    Start-Sleep -Seconds 3
    $results.Add((Invoke-Phase "PostgresDown"))

    Invoke-Compose start postgres
    Wait-Healthy "postgres"
    $results.Add((Invoke-Phase "Baseline"))

    Invoke-Compose stop redis
    Start-Sleep -Seconds 3
    $results.Add((Invoke-Phase "RedisDown"))

    Invoke-Compose start redis
    Wait-Healthy "redis"
    $results.Add((Invoke-Phase "Recovered"))

    [pscustomobject]@{
        schema_version = 1
        evidence = "disposable-local-compose"
        generated_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
        base_url_host = $base.Host
        phases = @($results)
        status = "passed"
    } | ConvertTo-Json -Depth 8 -Compress
}
catch {
    $operationError = $_.Exception.Message
}
finally {
    try {
        Invoke-Compose start postgres redis
        Wait-Healthy "postgres"
        Wait-Healthy "redis"
    }
    catch {
        $cleanupError = $_.Exception.Message
    }
    if ($cleanupError -and $operationError) {
        throw "Local Compose drill failed: $operationError Cleanup failed: $cleanupError"
    }
    if ($cleanupError) {
        throw "Local Compose cleanup failed: $cleanupError"
    }
    if ($operationError) {
        throw $operationError
    }
}
