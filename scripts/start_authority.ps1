# scripts/start_authority.ps1
# Run from the project root: .\scripts\start_authority.ps1

Set-Location $PSScriptRoot\..

.\venv\Scripts\Activate.ps1

$env:CANARY_SECRET           = "canary-secret-dev"
$env:AUTHORITY_MASTER_SECRET = "authority-master-secret-dev"
$env:MINIO_ENDPOINT          = "127.0.0.1:9000"
$env:MINIO_ACCESS_KEY        = "minioadmin"
$env:MINIO_SECRET_KEY        = "minioadmin"

Write-Host "Starting Authority service on https://0.0.0.0:8000 ..." -ForegroundColor Cyan

uvicorn authority.main:app `
    --host 0.0.0.0 `
    --port 8000 `
    --ssl-keyfile  ./certs/key.pem `
    --ssl-certfile ./certs/cert.pem
