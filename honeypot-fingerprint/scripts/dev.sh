#!/usr/bin/env bash
# Non-Docker dev run: backend on :8000, Vite dev server on :5173 (proxying /api and /ws).
set -euo pipefail
cd "$(dirname "$0")/.."

PY=backend/.venv/bin/python
[ -x "$PY" ] || PY=backend/.venv/Scripts/python.exe
if [ ! -x "$PY" ]; then
  echo "Creating backend venv..."
  (cd backend && (uv venv --python 3.11 .venv || python3.11 -m venv .venv))
  PY=backend/.venv/bin/python; [ -x "$PY" ] || PY=backend/.venv/Scripts/python.exe
  (cd backend && (uv pip install --python "../$PY" -r requirements.txt || "../$PY" -m pip install -r requirements.txt))
fi
[ -d frontend/node_modules ] || (cd frontend && npm install)

(cd backend && "../$PY" -m uvicorn app.main:app --port 8000) &
BACK=$!
trap 'kill $BACK 2>/dev/null' EXIT
cd frontend && npm run dev
