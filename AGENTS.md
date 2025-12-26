# Repository Guidelines

## Project Structure & Module Organization
- App entrypoint: `frida_script.py` (Flask UI for running Frida).
- AI bridge: `codex-bridge.py` (MCP/Codex integration); optional `claude-bridge.py`.
- Scripts: `scripts/` (Frida JS samples) plus `Script Directory 1` and `Script Directory 2`.
- Web assets: `templates/` (Jinja2 HTML), `static/` (css/js/img/data).
- Device helpers: `frida-server/`, `setup-adb.(sh|bat)`.
- Temp and artifacts: `tmp/`, `temp_generated.js`, `dump.(py|js)`.
- Containerization: `Dockerfile`, `docker-compose.yml`.

## Build, Test, and Development Commands
- Install deps (local): `python -m venv venv && pip install -r requirements.txt`.
- Run app (local): `python frida_script.py --port 5000` → http://127.0.0.1:5000.
- Run AI bridge (optional): `python codex-bridge.py` → http://127.0.0.1:8091.
- Docker (app only): `docker-compose up --build` (supports `FRIDA_VERSION` build-arg in `Dockerfile`).
- ADB setup: `./setup-adb.sh` (Linux/macOS) or `setup-adb.bat` (Windows).

## Coding Style & Naming Conventions
- Language: Python 3.11. Indentation: 4 spaces. Follow PEP 8.
- Names: modules/functions `snake_case`, classes `PascalCase`, constants `UPPER_SNAKE_CASE`.
- Type hints preferred for new/changed functions.
- Web: keep UI logic in `templates/`, static assets under `static/js` and `static/css`.
- Keep changes minimal and localized; avoid broad refactors in feature PRs.

## Testing Guidelines
- No formal unit test suite yet. Validate changes by:
  - Running the Flask app and verifying key flows (script run, package list, APK/IPA dump).
  - Exercising endpoints (e.g., `POST /run_frida`, `POST /generate-frida-script`).
- If adding tests, prefer `pytest`; place files under `tests/` as `test_*.py` and run `pytest -q`.

## Commit & Pull Request Guidelines
- Use Conventional Commits: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `build:`. Scope optional.
- Commits should be small and focused; describe the why and the impact.
- PRs must include: summary, screenshots or curl examples when UI/API changes, steps to verify, and linked issues.
- Update `README.md`, `.env.example`, and docs when configs, ports, or endpoints change.

## Security & Configuration
- Do not commit secrets. Use `.env` (see `.env.example`) and `.config.toml` derived from `.config.toml.example` for MCP paths.
- For Docker + ADB, ensure `ADB_SERVER_SOCKET=tcp:host.docker.internal:5037` (already set in `docker-compose.yml`).
- Confirm Frida server runs on device before testing; pin version via `FRIDA_VERSION` when needed.

