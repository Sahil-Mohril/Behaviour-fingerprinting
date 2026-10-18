.PHONY: install dev backend frontend test test-backend test-frontend demo docker-up docker-down clean

VPY ?= .venv/bin/python
ifeq ($(OS),Windows_NT)
VPY := .venv/Scripts/python.exe
endif
PY := backend/$(VPY)

install:
	cd backend && (uv venv --python 3.11 .venv || python3.11 -m venv .venv)
	cd backend && (uv pip install --python $(VPY) -r requirements.txt || $(VPY) -m pip install -r requirements.txt)
	cd frontend && npm install

# Backend on :8000 and the Vite dev server on :5173 (proxies /api and /ws)
dev:
	./scripts/dev.sh

backend:
	cd backend && $(VPY) -m uvicorn app.main:app --reload --port 8000

frontend:
	cd frontend && npm run dev

test: test-backend test-frontend

test-backend:
	cd backend && $(VPY) -m pytest -q

test-frontend:
	cd frontend && npm test && npm run smoke

demo:
	cd backend && $(VPY) -m app.demo

docker-up:
	docker compose up --build

docker-down:
	docker compose down

clean:
	rm -rf backend/state frontend/dist
