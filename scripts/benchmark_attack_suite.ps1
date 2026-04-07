param(
    [string]$AuthorityBaseUrl = "http://127.0.0.1:8000",
    [string]$CanaryBaseUrl = "http://127.0.0.1:8002",
    [int]$Runs = 30,
    [string]$Scenarios = "invalid_signature_threshold,canary_then_probe,key_mismatch,not_authorized,stale_timestamp_threshold",
    [int]$ThresholdAttempts = 3,
    [string]$OutputDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $Message"
}

function Invoke-Api {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("GET", "POST")] [string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [object]$Body = $null
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if ($Method -eq "GET") {
            $resp = Invoke-RestMethod -Method Get -Uri $Uri -TimeoutSec 10
        }
        else {
            $resp = Invoke-RestMethod -Method Post -Uri $Uri -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 8) -TimeoutSec 10
        }
        $sw.Stop()
        return @{
            ok = $true
            duration_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            response = $resp
            error = $null
        }
    }
    catch {
        $sw.Stop()
        return @{
            ok = $false
            duration_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
            response = $null
            error = $_.Exception.Message
        }
    }
}

function New-BadSignatureB64 {
    param([string]$Seed)
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Seed))
}

function Get-Targets {
    param([string]$AuthorityBaseUrl)
    $filesRes = Invoke-Api -Method GET -Uri "$($AuthorityBaseUrl.TrimEnd('/'))/files"
    if (-not $filesRes.ok) {
        throw "Failed to fetch /files: $($filesRes.error)"
    }
    $files = @($filesRes.response)
    if ($files.Count -eq 0) {
        throw "No files found in authority. Upload at least one file before running benchmark."
    }
    return ,$files
}

function Invoke-RequestShare {
    param(
        [string]$AuthorityBaseUrl,
        [string]$KeyId,
        [string]$FileId,
        [string]$ClientId,
        [string]$Nonce,
        [string]$RequestTs,
        [string]$SignatureB64
    )
    $body = @{
        key_id = $KeyId
        client_id = $ClientId
        file_id = $FileId
        nonce = $Nonce
        request_ts = $RequestTs
        signature_b64 = $SignatureB64
    }
    $res = Invoke-Api -Method POST -Uri "$($AuthorityBaseUrl.TrimEnd('/'))/request_share" -Body $body
    return @{
        request = $body
        api = $res
    }
}

function Run-InvalidSignatureThreshold {
    param($ctx)
    $attempts = @()
    $poisoned_at = $null
    for ($i = 1; $i -le $ctx.ThresholdAttempts; $i++) {
        $r = Invoke-RequestShare `
            -AuthorityBaseUrl $ctx.AuthorityBaseUrl `
            -KeyId $ctx.KeyId `
            -FileId $ctx.FileId `
            -ClientId $ctx.ClientId `
            -Nonce ([guid]::NewGuid().ToString()) `
            -RequestTs ((Get-Date).ToUniversalTime().ToString("o")) `
            -SignatureB64 (New-BadSignatureB64 -Seed "bad-sig-$i")
        $attempts += @{
            attempt = $i
            duration_ms = $r.api.duration_ms
            ok = $r.api.ok
            error = $r.api.error
            response = $r.api.response
        }
        if ($r.api.ok -and $r.api.response.key_status -eq "POISONED" -and $null -eq $poisoned_at) {
            $poisoned_at = $i
        }
    }
    return @{
        scenario = "invalid_signature_threshold"
        attempts = $attempts
        poisoned_at_attempt = $poisoned_at
    }
}

function Run-CanaryThenProbe {
    param($ctx)
    $canaryRes = Invoke-Api -Method GET -Uri "$($ctx.CanaryBaseUrl.TrimEnd('/'))/request_canary_share?key_id=$([uri]::EscapeDataString($ctx.KeyId))&requester_id=mallory-benchmark"
    Start-Sleep -Milliseconds 400
    $probe = Invoke-RequestShare `
        -AuthorityBaseUrl $ctx.AuthorityBaseUrl `
        -KeyId $ctx.KeyId `
        -FileId $ctx.FileId `
        -ClientId $ctx.ClientId `
        -Nonce ([guid]::NewGuid().ToString()) `
        -RequestTs ((Get-Date).ToUniversalTime().ToString("o")) `
        -SignatureB64 (New-BadSignatureB64 -Seed "post-canary-probe")
    return @{
        scenario = "canary_then_probe"
        canary = $canaryRes
        probe = @{
            duration_ms = $probe.api.duration_ms
            ok = $probe.api.ok
            error = $probe.api.error
            response = $probe.api.response
        }
    }
}

function Run-KeyMismatch {
    param($ctx)
    $wrongKeyId = "key-wrong-$([guid]::NewGuid())"
    $r = Invoke-RequestShare `
        -AuthorityBaseUrl $ctx.AuthorityBaseUrl `
        -KeyId $wrongKeyId `
        -FileId $ctx.FileId `
        -ClientId $ctx.ClientId `
        -Nonce ([guid]::NewGuid().ToString()) `
        -RequestTs ((Get-Date).ToUniversalTime().ToString("o")) `
        -SignatureB64 (New-BadSignatureB64 -Seed "mismatch")
    return @{
        scenario = "key_mismatch"
        wrong_key_id = $wrongKeyId
        result = @{
            duration_ms = $r.api.duration_ms
            ok = $r.api.ok
            error = $r.api.error
            response = $r.api.response
        }
    }
}

function Run-NotAuthorized {
    param($ctx)
    $unauthClient = "client-unauth-$([guid]::NewGuid())"
    $r = Invoke-RequestShare `
        -AuthorityBaseUrl $ctx.AuthorityBaseUrl `
        -KeyId $ctx.KeyId `
        -FileId $ctx.FileId `
        -ClientId $unauthClient `
        -Nonce ([guid]::NewGuid().ToString()) `
        -RequestTs ((Get-Date).ToUniversalTime().ToString("o")) `
        -SignatureB64 (New-BadSignatureB64 -Seed "unauth")
    return @{
        scenario = "not_authorized"
        unauth_client_id = $unauthClient
        result = @{
            duration_ms = $r.api.duration_ms
            ok = $r.api.ok
            error = $r.api.error
            response = $r.api.response
        }
    }
}

function Run-StaleTimestampThreshold {
    param($ctx)
    $attempts = @()
    $poisoned_at = $null
    for ($i = 1; $i -le $ctx.ThresholdAttempts; $i++) {
        $staleTs = (Get-Date).ToUniversalTime().AddMinutes(-15).ToString("o")
        $r = Invoke-RequestShare `
            -AuthorityBaseUrl $ctx.AuthorityBaseUrl `
            -KeyId $ctx.KeyId `
            -FileId $ctx.FileId `
            -ClientId $ctx.ClientId `
            -Nonce ([guid]::NewGuid().ToString()) `
            -RequestTs $staleTs `
            -SignatureB64 (New-BadSignatureB64 -Seed "stale-$i")
        $attempts += @{
            attempt = $i
            duration_ms = $r.api.duration_ms
            ok = $r.api.ok
            error = $r.api.error
            response = $r.api.response
        }
        if ($r.api.ok -and $r.api.response.key_status -eq "POISONED" -and $null -eq $poisoned_at) {
            $poisoned_at = $i
        }
    }
    return @{
        scenario = "stale_timestamp_threshold"
        attempts = $attempts
        poisoned_at_attempt = $poisoned_at
    }
}

$scenarioList = $Scenarios.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
if ($scenarioList.Count -eq 0) {
    throw "No scenarios selected."
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputDir = Join-Path $PSScriptRoot "benchmark-results\$stamp"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Step "Output directory: $OutputDir"
Write-Step "Fetching target files from authority..."
$targets = Get-Targets -AuthorityBaseUrl $AuthorityBaseUrl
Write-Step "Found $($targets.Count) file targets."

$results = @()

for ($run = 1; $run -le $Runs; $run++) {
    $target = $targets[($run - 1) % $targets.Count]
    $ctx = @{
        AuthorityBaseUrl = $AuthorityBaseUrl
        CanaryBaseUrl = $CanaryBaseUrl
        ThresholdAttempts = $ThresholdAttempts
        KeyId = [string]$target.key_id
        FileId = [string]$target.file_id
        ClientId = [string]$target.uploader_id
        AuthorizedClients = @($target.authorized_clients)
        Run = $run
    }

    Write-Step "Run $run/$Runs on key_id=$($ctx.KeyId) file_id=$($ctx.FileId)"
    $runResult = @{
        run = $run
        timestamp = (Get-Date).ToString("o")
        target = @{
            key_id = $ctx.KeyId
            file_id = $ctx.FileId
            uploader_client_id = $ctx.ClientId
            authorized_clients = $ctx.AuthorizedClients
        }
        scenarios = @()
    }

    foreach ($scenario in $scenarioList) {
        Write-Step "  Scenario: $scenario"
        switch ($scenario) {
            "invalid_signature_threshold" {
                $runResult.scenarios += (Run-InvalidSignatureThreshold -ctx $ctx)
            }
            "canary_then_probe" {
                $runResult.scenarios += (Run-CanaryThenProbe -ctx $ctx)
            }
            "key_mismatch" {
                $runResult.scenarios += (Run-KeyMismatch -ctx $ctx)
            }
            "not_authorized" {
                $runResult.scenarios += (Run-NotAuthorized -ctx $ctx)
            }
            "stale_timestamp_threshold" {
                $runResult.scenarios += (Run-StaleTimestampThreshold -ctx $ctx)
            }
            default {
                $runResult.scenarios += @{
                    scenario = $scenario
                    error = "Unknown scenario"
                }
            }
        }
    }

    $runPath = Join-Path $OutputDir ("run-{0:D3}.json" -f $run)
    $runResult | ConvertTo-Json -Depth 20 | Set-Content -Path $runPath -Encoding UTF8
    $results += $runResult
}

$manifest = @{
    generated_at = (Get-Date).ToString("o")
    authority_base_url = $AuthorityBaseUrl
    canary_base_url = $CanaryBaseUrl
    runs = $Runs
    scenarios = $scenarioList
    threshold_attempts = $ThresholdAttempts
    output_dir = $OutputDir
    files_found = $targets.Count
}
$manifestPath = Join-Path $OutputDir "manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

Write-Host ""
Write-Host "Benchmark run complete."
Write-Host "Results directory: $OutputDir"
Write-Host "Manifest: $manifestPath"
Write-Host "Next step:"
Write-Host "python scripts/analyze_benchmark_results.py --input `"$OutputDir`""
