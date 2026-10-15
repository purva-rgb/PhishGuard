# Phishing Email Detector

## Backend (Stage 1: skeleton)

The backend currently only receives emails. It does not analyze anything yet.

Requires Python 3.11+. All commands below are run from the `backend` folder (PowerShell on Windows).

### 1. Create a virtual environment

```powershell
cd phishing-detector\backend
python -m venv .venv
.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
cd phishing-detector/backend
python3 -m venv .venv
source .venv/bin/activate
```

If PowerShell blocks activation, run once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Start FastAPI

```powershell
uvicorn app.main:app --reload
```

The server runs at http://127.0.0.1:8000 (interactive docs at http://127.0.0.1:8000/docs).

### 4. Test GET /health

In a second terminal:

```powershell
curl.exe http://127.0.0.1:8000/health
```

Expected: `{"status":"ok"}`

### 5. Test POST /api/analyze/email

Valid request (PowerShell):

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/analyze/email `
  -ContentType "application/json" `
  -Body '{"email_text": "Hello, please verify your account."}'
```

Expected (Stage 2: the email is parsed into structured fields; headers that are absent become
`null`, and SPF/DKIM/DMARC become `"unknown"`):

```json
{"status": "parsed", "email": {"from": null, "to": [], "subject": null, "spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "plain_text_body": "Hello, please verify your account.", "...": "..."}}
```

Realistic sample email with headers, Authentication-Results and a multipart body
(`sample_request.json`):

```powershell
curl.exe -s -X POST http://127.0.0.1:8000/api/analyze/email -H "Content-Type: application/json" --data-binary "@sample_request.json"
```

Same request with curl (macOS/Linux):

```bash
curl -X POST http://127.0.0.1:8000/api/analyze/email \
  -H "Content-Type: application/json" \
  -d '{"email_text": "Hello, please verify your account."}'
```

Invalid requests (empty or whitespace-only `email_text`) return HTTP `422`:

```powershell
curl.exe -i -X POST http://127.0.0.1:8000/api/analyze/email -H "Content-Type: application/json" -d "{\"email_text\": \"   \"}"
```

### 6. Run the automated tests

```powershell
python -m pytest
```

## Configuration

CORS allows `http://localhost:3000` and `http://localhost:5173` by default. To change this, set the
`CORS_ORIGINS` environment variable (comma-separated); see `.env.example`.
