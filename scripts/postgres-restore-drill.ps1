[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceDatabaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$DrillDatabaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$BackupRecipient,

    [Parameter(Mandatory = $true)]
    [string]$BackupIdentity,

    [Parameter(Mandatory = $true)]
    [string]$BackupPath,

    [int]$MinimumSchemaVersion = 25
)

$ErrorActionPreference = "Stop"

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

Require-Command "pg_dump"
Require-Command "pg_restore"
Require-Command "psql"
Require-Command "age"

if ([string]::IsNullOrWhiteSpace($SourceDatabaseUrl) -or
    [string]::IsNullOrWhiteSpace($DrillDatabaseUrl) -or
    $SourceDatabaseUrl -eq $DrillDatabaseUrl) {
    throw "Source and drill PostgreSQL URLs must both be set and must be different."
}
if ($MinimumSchemaVersion -lt 1) {
    throw "MinimumSchemaVersion must be positive."
}

function Get-DatabaseFingerprint([string]$DatabaseUrl, [string]$Label) {
    # URL strings are not enough to prove that the destructive restore target is
    # isolated: aliases, DNS, or query parameters can spell the same database
    # differently. Ask PostgreSQL for its own database/server identity before
    # creating or restoring any dump. The result is never printed.
    $query = "SELECT current_database() || '|' || COALESCE(inet_server_addr()::text, 'local') || '|' || COALESCE(inet_server_port()::text, 'local');"
    $raw = & psql --no-psqlrc --tuples-only --no-align --quiet --dbname $DatabaseUrl --command $query 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not verify the $Label PostgreSQL target."
    }
    $fingerprint = ($raw -join "").Trim()
    if ([string]::IsNullOrWhiteSpace($fingerprint) -or
        $fingerprint.Contains("`n") -or $fingerprint.Contains("`r")) {
        throw "Could not verify the $Label PostgreSQL target."
    }
    return $fingerprint
}

$sourceFingerprint = Get-DatabaseFingerprint $SourceDatabaseUrl "source"
$drillFingerprint = Get-DatabaseFingerprint $DrillDatabaseUrl "drill"
if ($sourceFingerprint -eq $drillFingerprint) {
    throw "Source and drill URLs resolve to the same PostgreSQL target/database; refusing destructive restore."
}

$resolvedBackup = [System.IO.Path]::GetFullPath($BackupPath)
if (Test-Path -LiteralPath $resolvedBackup) {
    throw "Refusing to overwrite an existing backup: $resolvedBackup"
}
$backupDirectory = Split-Path -Parent $resolvedBackup
if ($backupDirectory) {
    New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
}

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("llm-firewall-restore-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
$dumpPath = Join-Path $temporaryDirectory "control-plane.dump"
$restorePath = Join-Path $temporaryDirectory "control-plane.restore.dump"
$restoreSqlPath = Join-Path $temporaryDirectory "control-plane.restore.sql"

try {
    Write-Host "Creating encrypted PostgreSQL backup..."
    & pg_dump --format=custom --no-owner --no-privileges --file $dumpPath $SourceDatabaseUrl
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed." }

    & age --encrypt --recipient $BackupRecipient --output $resolvedBackup $dumpPath
    if ($LASTEXITCODE -ne 0) { throw "age encryption failed." }
    Remove-Item -LiteralPath $dumpPath -Force

    Write-Host "Decrypting backup into an isolated temporary file for the drill..."
    & age --decrypt --identity $BackupIdentity --output $restorePath $resolvedBackup
    if ($LASTEXITCODE -ne 0) { throw "age decryption failed." }

    Write-Host "Preparing a strict SQL restore for the explicitly supplied drill database..."
    # Newer pg_dump clients can emit SET transaction_timeout, which older
    # PostgreSQL servers reject. Render the custom archive first, then remove
    # only that capability-gated statement when the target does not expose the
    # setting. The actual restore still runs with ON_ERROR_STOP, so every other
    # incompatibility remains fatal instead of being hidden as a pg_restore warning.
    & pg_restore --clean --if-exists --no-owner --no-privileges --file $restoreSqlPath $restorePath
    if ($LASTEXITCODE -ne 0) { throw "pg_restore SQL rendering failed." }
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & psql --no-psqlrc --tuples-only --no-align --quiet --dbname $DrillDatabaseUrl `
        --command "SELECT current_setting('transaction_timeout');" 2>$null
    $transactionTimeoutSupported = $LASTEXITCODE -eq 0
    $ErrorActionPreference = $previousErrorActionPreference
    if (-not $transactionTimeoutSupported) {
        $sql = [System.IO.File]::ReadAllText($restoreSqlPath)
        $sql = [regex]::Replace($sql, '(?m)^\s*SET transaction_timeout = 0;\s*\r?\n', '')
        [System.IO.File]::WriteAllText(
            $restoreSqlPath,
            $sql,
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    & psql --no-psqlrc --quiet --set ON_ERROR_STOP=1 --dbname $DrillDatabaseUrl --file $restoreSqlPath
    if ($LASTEXITCODE -ne 0) { throw "psql restore failed." }

    $schemaVersion = (& psql --no-psqlrc --tuples-only --no-align --dbname $DrillDatabaseUrl --command "SELECT COALESCE(MAX(version), 0) FROM llm_firewall_schema_migrations;").Trim()
    if ($LASTEXITCODE -ne 0) { throw "Could not read the restored schema version." }
    $parsedSchemaVersion = 0
    if (-not [int]::TryParse($schemaVersion, [ref]$parsedSchemaVersion) -or $parsedSchemaVersion -lt $MinimumSchemaVersion) {
        throw "Restored schema version '$schemaVersion' is below required version $MinimumSchemaVersion."
    }

    $evidence = (& psql --no-psqlrc --tuples-only --no-align --dbname $DrillDatabaseUrl --command "SELECT (SELECT COUNT(*) FROM tenant_security_events), (SELECT COUNT(*) FROM tenant_webhook_deliveries), (SELECT COUNT(*) FROM workspace_service_accounts);").Trim()
    if ($LASTEXITCODE -ne 0) { throw "Could not verify restored control-plane evidence tables." }
    Write-Host "Restore drill passed. Schema version: $parsedSchemaVersion. Evidence counts: $evidence"
    Write-Host "Keep the encrypted backup under the approved retention policy; destroy the drill database separately."
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
