# Non-Docker dev run on Windows: backend on :8000, Vite dev server on :5173.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$py = Join-Path $root "backend\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
  Write-Host "Creating backend venv (uv, Python 3.11)..."
  Push-Location backend
  uv venv --python 3.11 .venv
  uv pip install --python .venv\Scripts\python.exe -r requirements.txt
  Pop-Location
}
if (-not (Test-Path "frontend\node_modules")) { Push-Location frontend; npm install; Pop-Location }

$backend = Start-Process -FilePath $py -ArgumentList "-m", "uvicorn", "app.main:app", "--port", "8000" `
  -WorkingDirectory (Join-Path $root "backend") -PassThru -NoNewWindow
try {
  Push-Location frontend
  npm run dev
} finally {
  Pop-Location
  Stop-Process -Id $backend.Id -ErrorAction SilentlyContinue
}
