# ECDAT frontend

React, TypeScript and Vite frontend. See the [root README](../README.md) for full usage, policies, backend setup, security and operations.

```powershell
npm ci
npm run dev
npm run build
npm run lint
```

Development URL: http://localhost:5173. Vite proxies the API to http://127.0.0.1:8000. On Windows, use `setup.bat frontend` from the root directory. Docker serves the built application on http://localhost:3000. The workspace uses actual saved scans and reports; no chatbot or seeded demo inventory is required.

Windows local setup: run `setup.bat`, edit admin credentials in root `.env` from the root, then `setup.bat backend` and `setup.bat frontend` in separate terminals. The `.env` administrator adds normal accounts through Users; scan data stays separate per account. See the root README.
