# scripts/start_canary.ps1
# Run from the project root: .\scripts\start_canary.ps1

Set-Location $PSScriptRoot\..

.\venv\Scripts\Activate.ps1

$env:AUTHORITY_BASE_URL = "https://127.0.0.1:8000"
$env:CANARY_SECRET      = "canary-secret-dev"

Write-Host "Starting Canary service on https://0.0.0.0:8002 ..." -ForegroundColor Yellow

uvicorn canary.canary_service:app `
    --host 0.0.0.0 `
    --port 8002 `
    --ssl-keyfile  ./certs/key.pem `
    --ssl-certfile ./certs/cert.pem
