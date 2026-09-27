# ECDAT backend

See the [root development and operations README](../README.md) for supported inputs, setup, API contracts, policies, access control, limitations and troubleshooting.

From this directory:

```powershell
uv sync --extra dev
uv run uvicorn ecdat.apps.api.main:app --host 127.0.0.1 --port 8000 --reload
uv run pytest tests/unit tests/security tests/integration tests/performance -q
uv run ecdat --help
```

The active workspace is filesystem-backed. Accounts and session digests use an embedded SQLite file; scan records remain files. Set `AUTH_USERNAME` and `AUTH_PASSWORD` in root `.env` before starting the API. On Windows, use `setup.bat` in the repository root for one-click dependency installation and server execution. Legacy database/worker modules were removed. Use a single API process for scan ownership.

Windows local setup: run `setup.bat`, edit admin credentials in root `.env` from the root, then `setup.bat backend` and `setup.bat frontend` in separate terminals. The `.env` administrator adds normal accounts through Users; scan data stays separate per account. See the root README.
