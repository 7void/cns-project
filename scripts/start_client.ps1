# scripts/start_client.ps1
# Run from the project root: .\scripts\start_client.ps1

Set-Location $PSScriptRoot\..

.\venv\Scripts\Activate.ps1

$env:AUTHORITY_BASE_URL = "https://127.0.0.1:8000"
$env:CANARY_BASE_URL    = "https://127.0.0.1:8002"
$env:MINIO_ENDPOINT     = "127.0.0.1:9000"
$env:MINIO_ACCESS_KEY   = "minioadmin"
$env:MINIO_SECRET_KEY   = "minioadmin"

Write-Host "Starting Client UI on http://localhost:8501 ..." -ForegroundColor Green
Write-Host "(Authority: $env:AUTHORITY_BASE_URL | Canary: $env:CANARY_BASE_URL)" -ForegroundColor DarkGray

streamlit run ui/client_ui.py
