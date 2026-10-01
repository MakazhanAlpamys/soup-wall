[CmdletBinding()]
param(
    # Pin the disposable image by digest so a later tag move cannot silently
    # change the runtime being measured.
    [string]$Image = "debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171",

    # If omitted, create an owned temporary workspace and remove it on exit.
    # A caller-provided workspace is never removed; only one unique marker file
    # is created and cleaned up there.
    [string]$Workspace = "",

    # Optional Docker runtime, for example `runsc` on a gVisor-enabled host.
    # The default uses the host's configured runtime and reports that fact in
    # the evidence; production must select and review its isolation runtime.
    [string]$Runtime = ""
)

$ErrorActionPreference = "Stop"

function Invoke-Docker([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments) {
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        # Docker writes progress to stderr even when a command succeeds. Keep
        # that progress out of the JSON evidence and only surface it on error.
        $ErrorActionPreference = "Continue"
        $output = @(& docker @Arguments 2>&1)
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
        throw "docker $($Arguments -join ' ') failed with exit code $exitCode. $detail"
    }
}

if ($Runtime -and $Runtime.Length -gt 128 -or $Runtime -and $Runtime.IndexOfAny([char[]]"`0`r`n") -ge 0) {
    throw "Runtime is invalid."
}

Invoke-Docker info

$ownedWorkspace = $false
if ([string]::IsNullOrWhiteSpace($Workspace)) {
    $Workspace = Join-Path ([System.IO.Path]::GetTempPath()) (
        "soup-wall-container-sandbox-" + [Guid]::NewGuid().ToString("N")
    )
    New-Item -ItemType Directory -Path $Workspace | Out-Null
    $ownedWorkspace = $true
}
else {
    if (-not (Test-Path -LiteralPath $Workspace -PathType Container)) {
        throw "Workspace must be an existing directory when supplied: $Workspace"
    }
}

$workspacePath = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Workspace).Path)
$markerName = ".soup-wall-sandbox-marker-" + [Guid]::NewGuid().ToString("N") + ".txt"
$markerPath = Join-Path $workspacePath $markerName
$containerName = "soup-wall-container-sandbox-" + [Guid]::NewGuid().ToString("N")

$containerArgs = @(
    "run",
    "--rm",
    "--name", $containerName,
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--pids-limit", "64",
    "--memory", "256m",
    "--cpus", "1",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
    "--mount", "type=bind,src=$workspacePath,dst=/workspace,readonly=false"
)
if ($Runtime) {
    $containerArgs += @("--runtime", $Runtime)
}
$containerArgs += @(
    $Image,
    "sh",
    "-ceu",
    "printf sandbox-ok > /workspace/$markerName; test -f /workspace/$markerName; ! touch /etc/escape; test ! -s /proc/net/route; if getent hosts example.com >/dev/null 2>&1; then exit 42; fi; test -w /tmp"
)

$cleanupError = $null
try {
    Invoke-Docker @containerArgs
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw "Sandbox did not write its isolated workspace marker."
    }
    if ((Get-Content -Raw -LiteralPath $markerPath) -ne "sandbox-ok") {
        throw "Sandbox workspace marker had unexpected content."
    }

    [pscustomobject]@{
        schema_version = 1
        evidence = "disposable-hardened-container"
        generated_at_utc = [DateTimeOffset]::UtcNow.ToString("O")
        image = $Image
        runtime = if ($Runtime) { $Runtime } else { "docker-default" }
        network = "none"
        root_filesystem_read_only = $true
        capabilities_dropped = "ALL"
        no_new_privileges = $true
        writable_mount = "/workspace"
        resource_limits = "pids=64,memory=256m,cpus=1"
        workspace_write = $true
        root_write_blocked = $true
        dns_egress_blocked = $true
        status = "passed"
    } | ConvertTo-Json -Depth 5 -Compress
}
finally {
    try {
        if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
            Remove-Item -LiteralPath $markerPath -Force
        }
        if ($ownedWorkspace -and (Test-Path -LiteralPath $workspacePath -PathType Container)) {
            Remove-Item -LiteralPath $workspacePath -Recurse -Force
        }
    }
    catch {
        $cleanupError = $_.Exception.Message
    }
    if ($cleanupError) {
        throw "Container sandbox cleanup failed: $cleanupError"
    }
}
