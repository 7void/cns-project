param(
    [string]$AuthorityBaseUrl = "http://127.0.0.1:8000",
    [string]$CanaryBaseUrl = "http://127.0.0.1:8002",
    [string]$KeyId = "",
    [string]$FileId = "",
    [string]$ImpersonatedClientId = "",
    [string]$AttackerId = "mallory",
    [int]$SuspiciousAttempts = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $Message"
}

function Try-InvokeRestMethod {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("GET", "POST")] [string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [object]$Body = $null
    )
    try {
        if ($Method -eq "GET") {
            return Invoke-RestMethod -Method Get -Uri $Uri -TimeoutSec 10
        }
        return Invoke-RestMethod -Method Post -Uri $Uri -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 8) -TimeoutSec 10
    }
    catch {
        return @{
            error = $true
            message = $_.Exception.Message
        }
    }
}

$evidence = @()

Write-Step "Starting attacker demo flow"
$evidence += @{
    event = "start"
    timestamp = (Get-Date).ToString("o")
    authority_base_url = $AuthorityBaseUrl
    canary_base_url = $CanaryBaseUrl
    attacker_id = $AttackerId
}

if ([string]::IsNullOrWhiteSpace($KeyId)) {
    Write-Step "KeyId not supplied. Attempting to resolve via /latest_key"
    $latest = Try-InvokeRestMethod -Method GET -Uri "$($AuthorityBaseUrl.TrimEnd('/'))/latest_key"
    $evidence += @{
        event = "latest_key_lookup"
        timestamp = (Get-Date).ToString("o")
        response = $latest
    }
    if ($latest.error -or [string]::IsNullOrWhiteSpace([string]$latest.key_id)) {
        throw "Could not resolve key_id from /latest_key. Supply -KeyId explicitly (and set CNS_DEMO_MODE=true if you want /latest_key)."
    }
    $KeyId = [string]$latest.key_id
}

Write-Step "Using key_id=$KeyId"

if ([string]::IsNullOrWhiteSpace($FileId) -or [string]::IsNullOrWhiteSpace($ImpersonatedClientId)) {
    Write-Step "Resolving file metadata from /files"
    $files = Try-InvokeRestMethod -Method GET -Uri "$($AuthorityBaseUrl.TrimEnd('/'))/files"
    $evidence += @{
        event = "files_lookup"
        timestamp = (Get-Date).ToString("o")
        response = $files
    }

    if ($files.error) {
        throw "Failed to query /files: $($files.message)"
    }

    $matched = $null
    foreach ($f in $files) {
        if ([string]$f.key_id -eq $KeyId) {
            $matched = $f
            break
        }
    }

    if ($null -eq $matched) {
        throw "No file record found for key_id=$KeyId. Provide -FileId and -ImpersonatedClientId explicitly."
    }

    if ([string]::IsNullOrWhiteSpace($FileId)) {
        $FileId = [string]$matched.file_id
    }
    if ([string]::IsNullOrWhiteSpace($ImpersonatedClientId)) {
        $ImpersonatedClientId = [string]$matched.uploader_id
    }
}

Write-Step "Using file_id=$FileId and impersonated_client_id=$ImpersonatedClientId"

Write-Step "Attacker calls canary honeypot endpoint"
$canaryResp = Try-InvokeRestMethod -Method GET -Uri "$($CanaryBaseUrl.TrimEnd('/'))/request_canary_share?key_id=$([uri]::EscapeDataString($KeyId))&requester_id=$([uri]::EscapeDataString($AttackerId))"
$evidence += @{
    event = "request_canary_share"
    timestamp = (Get-Date).ToString("o")
    response = $canaryResp
}

Start-Sleep -Milliseconds 800

Write-Step "Attacker performs suspicious authority share requests (invalid signature)"
for ($i = 1; $i -le $SuspiciousAttempts; $i++) {
    $shareReq = @{
        key_id = $KeyId
        client_id = $ImpersonatedClientId
        file_id = $FileId
        nonce = [guid]::NewGuid().ToString()
        request_ts = (Get-Date).ToUniversalTime().ToString("o")
        signature_b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("invalid-demo-signature-$i"))
    }
    $shareResp = Try-InvokeRestMethod -Method POST -Uri "$($AuthorityBaseUrl.TrimEnd('/'))/request_share" -Body $shareReq
    $evidence += @{
        event = "request_share_suspicious_attempt"
        attempt = $i
        timestamp = (Get-Date).ToString("o")
        request = $shareReq
        response = $shareResp
    }
    Start-Sleep -Milliseconds 250
}

Write-Step "Collecting forensic log for key"
$forensicResp = Try-InvokeRestMethod -Method GET -Uri "$($AuthorityBaseUrl.TrimEnd('/'))/forensic_log?key_id=$([uri]::EscapeDataString($KeyId))"
$evidence += @{
    event = "forensic_log"
    timestamp = (Get-Date).ToString("o")
    response = $forensicResp
}

$runTs = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $PSScriptRoot "evidence"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$outPath = Join-Path $outDir "attack-demo-$runTs.json"

$payload = @{
    run_timestamp = (Get-Date).ToString("o")
    key_id = $KeyId
    file_id = $FileId
    impersonated_client_id = $ImpersonatedClientId
    attacker_id = $AttackerId
    evidence = $evidence
}

$payload | ConvertTo-Json -Depth 12 | Set-Content -Path $outPath -Encoding UTF8

Write-Step "Demo run complete"
Write-Host ""
Write-Host "Evidence file: $outPath"
Write-Host "Key checks:"
Write-Host "1) Canary endpoint response should contain status='ok' and canary_share_b64."
Write-Host "2) Suspicious request_share attempts should return denial_reason='invalid_signature'."
Write-Host "3) After threshold attempts, key status should transition to POISONED."
Write-Host "4) forensic_log may remain empty until a poisoned share is actually served."
