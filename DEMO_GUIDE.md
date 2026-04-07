# CNS Project Demo Guide

This guide is a complete, copy-paste workflow to run a full demo of the CNS prototype.

It covers:
- Server setup (Authority + Canary + MinIO)
- Client setup (Streamlit UI)
- Normal workflow demo
- Manual attacker workflow demo
- Expected outputs and troubleshooting

## 1) Demo Modes

You can run this demo in two ways:

1. Single-machine local demo (all services + UI on one machine)
2. Two-machine demo (server machine runs services, client machine runs UI)

---

## 2) Prerequisites

- Windows + PowerShell
- Python virtual environment in this repo (`venv`)
- Docker running (for MinIO)
- Dependencies installed (`requirements.txt`)
- Open ports:
  - `8000` (Authority)
  - `8002` (Canary)
  - `9000` (MinIO API)
  - `9001` (MinIO Console)

---

## 3) Start Services (Server Side)

Open 3 terminals on the server machine.

### Terminal S1 - Authority

```powershell
cd C:\Users\ahana\Documents\cns-project
.\venv\Scripts\Activate.ps1
$env:CANARY_SECRET="canary-secret-dev"
$env:AUTHORITY_MASTER_SECRET="dev-master-secret-change-in-prod"
uvicorn authority.main:app --host 0.0.0.0 --port 8000
```

### Terminal S2 - Canary

```powershell
cd C:\Users\ahana\Documents\cns-project
.\venv\Scripts\Activate.ps1
$env:CANARY_SECRET="canary-secret-dev"
$env:AUTHORITY_BASE_URL="http://127.0.0.1:8000"
uvicorn canary.canary_service:app --host 0.0.0.0 --port 8002
```

### Terminal S3 - MinIO

```powershell
docker run -p 9000:9000 -p 9001:9001 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data --console-address ":9001"
```

---

## 4) Start Client UI

Use one terminal on the client machine.

If you are running on a separate client machine, replace `SERVER_IP` with the server LAN IP.

```powershell
cd C:\Users\ahana\Documents\cns-project
.\venv\Scripts\Activate.ps1
$env:MINIO_ENDPOINT="SERVER_IP:9000"
$env:MINIO_ACCESS_KEY="minioadmin"
$env:MINIO_SECRET_KEY="minioadmin"
$env:AUTHORITY_BASE_URL="http://SERVER_IP:8000"
$env:CANARY_BASE_URL="http://SERVER_IP:8002"
streamlit run ui/client_ui.py
```

Single-machine local values:

```powershell
$env:MINIO_ENDPOINT="127.0.0.1:9000"
$env:AUTHORITY_BASE_URL="http://127.0.0.1:8000"
$env:CANARY_BASE_URL="http://127.0.0.1:8002"
```

---

## 5) Normal Demo Flow (In UI)

1. Open Streamlit page.
2. Set:
   - Authority URL: `http://<server-ip>:8000`
   - Canary URL: `http://<server-ip>:8002`
3. Register user (or login existing user).
4. Click `Refresh Available Clients`.
5. Upload a file, select at least one authorized client, click `Encrypt + Upload + Register`.
6. Click `Refresh Accessible Files`.
7. Select the uploaded file and click `Request Share + Decrypt`.
8. Verify successful decryption output.

---

## 6) Manual Attacker Demo (PowerShell)

Open a separate terminal (attacker terminal).

### Step A - Set URLs and choose target

```powershell
$authority = "http://127.0.0.1:8000"
$canary = "http://127.0.0.1:8002"

$files = Invoke-RestMethod "$authority/files"
$target = $files[0]   # change index if needed

$keyId = $target.key_id
$fileId = $target.file_id
$receiverClientId = $target.authorized_clients[0]

$keyId
$fileId
$receiverClientId
```

### Step B - Canary access (tripwire)

```powershell
Invoke-RestMethod "$canary/request_canary_share?key_id=$keyId&requester_id=mallory"
```

Expected: API returns status OK and canary share data to requester (deception behavior).

### Step C - Forged share requests (one by one)

```powershell
$b1 = @{
  key_id = $keyId
  client_id = $receiverClientId
  file_id = $fileId
  nonce = [guid]::NewGuid().ToString()
  request_ts = (Get-Date).ToUniversalTime().ToString("o")
  signature_b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("bad-sig-1"))
} | ConvertTo-Json
Invoke-RestMethod -Method POST "$authority/request_share" -ContentType "application/json" -Body $b1
```

```powershell
$b2 = @{
  key_id = $keyId
  client_id = $receiverClientId
  file_id = $fileId
  nonce = [guid]::NewGuid().ToString()
  request_ts = (Get-Date).ToUniversalTime().ToString("o")
  signature_b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("bad-sig-2"))
} | ConvertTo-Json
Invoke-RestMethod -Method POST "$authority/request_share" -ContentType "application/json" -Body $b2
```

```powershell
$b3 = @{
  key_id = $keyId
  client_id = $receiverClientId
  file_id = $fileId
  nonce = [guid]::NewGuid().ToString()
  request_ts = (Get-Date).ToUniversalTime().ToString("o")
  signature_b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("bad-sig-3"))
} | ConvertTo-Json
Invoke-RestMethod -Method POST "$authority/request_share" -ContentType "application/json" -Body $b3
```

Expected: denied responses with reasons like `invalid_signature`, and key status moving to `POISONED`.

### Step D - Show evidence logs

```powershell
(Invoke-RestMethod "$authority/logs") | Where-Object { $_.file_id -eq $fileId }
```

Optional:

```powershell
Invoke-RestMethod "$authority/forensic_log?key_id=$keyId"
```

### Step E - Re-test decryption in UI

Back in UI, try decrypting same file again.  
Expected: decryption fails once poisoned behavior is in effect.

---

## 7) Quick Status Checks

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/healthz"
Invoke-RestMethod "http://127.0.0.1:8002/healthz"
```

---

## 8) Common Troubleshooting

1. Login fails on another machine for same user:
   - Device key binding is enabled; same account from different device key may fail.

2. Gibberish UI text:
   - Pull latest code and restart Streamlit.

3. MinIO errors:
   - Confirm Docker is running and `MINIO_ENDPOINT`, access key, secret key are correct.

4. Immediately seeing `POISONED` on first attacker request:
   - That key was likely already poisoned in a previous run.
   - Upload a fresh file to get a new `key_id`.

5. Remote client cannot connect:
   - Confirm services started with `--host 0.0.0.0`.
   - Open firewall ports 8000/8002/9000.

---

## 9) Demo Talking Points (Optional)

- Legitimate path requires Share 1 + Share 2.
- Share 3 is a canary tripwire not required in normal operation.
- Share 1 and Share 2 are both encrypted at rest.
- Share 2 release is gated by ACL, nonce/timestamp freshness, and device signature verification.
- Hostile probing triggers poisoning and irreversible lifecycle progression.

