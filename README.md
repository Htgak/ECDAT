# ECDAT: cryptographic discovery and quantum migration planning

ECDAT scans supported source, binary, library and saved container inputs, inventories cryptographic observations, applies explicit business context, and suggests migration options. The React workspace shows saved scans, inventory, Mosca assessments, baseline policy findings, algorithm suggestions and downloadable reports. There is no AI chatbot, external LLM requirement, seeded demonstration estate, or unnecessary database infrastructure.

This README describes the active application. The sections at the top of `handoff.md` detail recent architectural simplifications and verification results.

---

## Architecture Overview

ECDAT is designed as a streamlined, **filesystem-backed** cryptographic discovery and analysis platform. All scan artifacts, inventory records, and reports reside directly in the structured evidence store:

```
┌────────────────────────────────────────────────────────┐
│                   React 19 Frontend                    │
│    Overview • Inventory • Scans • Policies • Advisories │
└───────────────────────────┬────────────────────────────┘
                            │ HTTP / REST
┌───────────────────────────▼────────────────────────────┐
│                    FastAPI Backend                     │
│  Uploads & Collectors • Inline Risk Engine • Exports   │
└───────────────────────────┬────────────────────────────┘
                            │ JSON / CSV / CBOM
┌───────────────────────────▼────────────────────────────┐
│            Evidence Store (Filesystem / Volume)        │
│  /uploads/<tenant_id>/<scan_id>/                       │
│    ├── original (source / binary / archive)            │
│    ├── record.json & report.json                       │
│    ├── findings.csv                                    │
│    ├── cbom.cdx.json (CycloneDX 1.6)                   │
│    ├── results.sarif (SARIF 2.1.0)                     │
│    └── checksums.json (SHA-256)                        │
└────────────────────────────────────────────────────────┘
```

The stack requires **only 2 services**:
1. **`backend`**: FastAPI running on Python 3.11 with static AST scanners, binary analyzers, and inline risk assessment.
2. **`frontend`**: React 19 SPA served via Nginx with reverse proxy to `/api/v1`.

Legacy service infrastructure (PostgreSQL, Valkey/Redis, Open Policy Agent, Merkle tree ledgers, RFC 3161 TSA clients, and background worker queues) have been completely removed.

---

## Quick Start with Docker

Requirements: Docker Desktop with Linux containers and Docker Compose v2.

```powershell
# Copy environment file if not already present
if (!(Test-Path .env)) { Copy-Item .env.example .env }

# Set AUTH_USERNAME and a unique 15-128 character AUTH_PASSWORD in .env first.
# Build and start backend + frontend
docker compose up -d --build
docker compose ps
```

- **Frontend UI**: [http://localhost:3000](http://localhost:3000) (Sign in with the administrator credentials configured in `.env`)
- **API Health & Readiness**: [http://localhost:8000/health](http://localhost:8000/health) and [http://localhost:8000/ready](http://localhost:8000/ready)
- **OpenAPI Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs), after sign-in and only with `ENVIRONMENT=development` (the schema itself is also authenticated)

```powershell
# View logs
docker compose logs -f --tail 100

# Stop services
docker compose down
```

Named volume `evidence_store` preserves scan inputs and generated reports. Do not use `docker compose down -v` unless you intend to erase all stored scans.

---

## Administrator and individual users

`AUTH_USERNAME` and `AUTH_PASSWORD` in the root `.env` configure the **administrator**. After signing in, the admin can open **Users** (`/admin/users`) to create multiple normal accounts, reset their passwords, and disable or enable them. Server-side role checks enforce these permissions. Normal users cannot manage accounts or create administrators.

Every account has its own scans, inventory, recommendations and exports under `uploads/<stored-account-UUID>/`. Admin privileges manage accounts but **do not grant access to another user's scan data**. Disabling or resetting an account revokes its sessions without deleting its files.

There is no default password. Passwords must contain **15-128 characters**. If an older `.env` contains `admin/admin`, edit `AUTH_USERNAME` and `AUTH_PASSWORD` in root `.env` before starting the backend to replace it. Credentials in `.env` are private; the file is excluded from version control.

### Windows local quick start

Install `uv`, Node.js 20.19+, 22.12+ or 24+, and Git for repository scanning. From the repository root in PowerShell:

```powershell
.\setup.bat
# Edit root .env: set AUTH_USERNAME and a unique AUTH_PASSWORD (15-128 characters)
```

`setup.bat` installs pinned Python dependencies and npm packages, creating `.env` from `.env.example` only if absent. Set administrator credentials directly in root `.env`; startup synchronizes the administrator account. Existing configuration and user data are preserved.

Run the servers in separate terminals:

```powershell
# Terminal 1
.\setup.bat backend
```

```powershell
# Terminal 2
.\setup.bat frontend
```

Open **http://localhost:5173**, sign in as admin, and use **Users** to add normal accounts. Share each user's initial credentials privately. There is no public registration.

| Command | Action |
|---|---|
| `setup.bat` / `setup.bat install` | Install dependencies; does not launch servers |
| `setup.bat backend` | API on 127.0.0.1:8000 with development reload |
| `setup.bat frontend` | UI on 127.0.0.1:5173; refuses an occupied port |
| `setup.bat test` | Backend tests, frontend lint and build |

Scripts resolve paths from their own location. Both use `ecdat-backend/evidence_store` unless `EVIDENCE_STORE_PATH` is explicitly set; use the same absolute override in both terminals. Docker uses a separate volume. If Docker occupies port 8000, run `docker compose stop` first. The scripts never stop existing services or delete evidence. Ctrl+C stops a local server.

### Configuration, ownership and sessions

Root `.env` overrides `ecdat-backend/.env`; process environment variables override both. Restart the backend after changing credentials. For Docker, set strong `AUTH_USERNAME`/`AUTH_PASSWORD` credentials in `.env` before `docker compose up -d --build`; Compose passes them to startup synchronization.

Existing stored UUIDs are preserved. A new admin gets the legacy workspace UUID only if it is unassigned; otherwise it gets a fresh UUID. No existing user's files are reassigned. Environment password/role changes revoke sessions, and removed environment accounts are disabled. Optional `AUTH_USERS` imports remain supported for **normal** environment-managed users; they cannot redefine the admin. Prefer the Users screen for new accounts. Environment-managed passwords must be changed in `.env`.

Passwords use salted scrypt hashes; opaque one-hour sessions are stored as SHA-256 digests and delivered through HttpOnly, SameSite=Strict cookies. Logout revokes sessions. Changed environment credentials do not fall back to old stored passwords. Login throttling applies per account and peer. The bundled proxy shares a peer limit; arbitrary forwarded IP headers are not trusted.

For remote deployment, configure TLS, `SESSION_COOKIE_SECURE=true`, exact allowed hosts and origins. Batch startup intentionally uses localhost HTTP development settings. There is no MFA, SSO or self-service recovery; host administrators remain trusted. See [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and [session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

---

## Scan and Review Workflow

1. Open **Discovery scans** (`/scans`), choose an input type, and select a file or supported public Git repository URL.
2. Supply organizational context if known (data lifetime $X$, migration duration $Y$, quantum horizon scenario $Z$, criticality, sensitivity, exposure). Leave unknown fields blank; zero years is an explicit value, not an unknown value.
3. Start the scan. The API returns a scan ID and performs bounded background work; the UI polls status until completion or failure.
4. Read evidence, locations, configurations and limitations in the saved result.
5. Review **Crypto inventory** (`/assets`), **Policy compliance** (`/policies`) and **PQC advisories** (`/advisories`).
6. Download individual reports directly from the scan, or export combined workspace artifacts from **Exports & CBOM** (`/exports`).

### Supported Inputs and Boundaries

| Input | Active Analysis | Boundaries |
|---|---|---|
| **Source files / ZIP** | Python and Java AST observations; string pattern matching for other supported text languages; embedded metadata | Does not execute code or install dependencies |
| **Public Git repository** | Bounded HTTPS acquisition from GitHub, GitLab, or Bitbucket; saved source snapshot | No private credentials, SSH, submodules, or LFS checkouts; arbitrary hosts/local paths rejected |
| **APK** | Static archive and cryptographic string indicators | No Android runtime execution or dynamic hooking |
| **EXE / DLL** | PE header validation and static string indicators | No execution, unpacking, or deobfuscation |
| **Libraries** | `.so`, `.dll`, `.dylib`, `.a`, `.jar`, `.zip`; metadata and string indicators | Algorithm name in a binary does not establish runtime execution |
| **Containers** | Saved Docker/OCI/rootfs `.tar`, `.tar.gz`, `.tgz`; bounded layer extraction and whiteouts | No container execution or registry pulls; symlinks/devices omitted and disclosed |

Uploads are limited to **500 MiB** (multipart request budget 501 MiB). Archive expansion is bounded to **2 GiB**, with at most **5,000 entries/findings**.

---

## Assessment Model & Replacement Suggestions

Context applies to the scan and is inherited by its findings:
- **Mosca Planning Theorem ($X + Y > Z$)**:
  - $X$: Required data protection lifetime (years)
  - $Y$: System migration duration (years)
  - $Z$: Quantum threat horizon (estimated arrival of cryptographically relevant quantum computer)
  - Verdicts: `act_now` ($X + Y > Z$), `monitor` ($0 \le Z - X - Y \le 2$), `within_horizon` ($Z - X - Y > 2$), or `not_assessed` if inputs are missing.
- **Planning Score**: An explainable 0–100 heuristic based on temporal urgency (40%), business criticality (25%), data sensitivity (20%), and exposure (15%).
- **PQC Migration Advisories**:
  - Distinguishes digital signatures from key establishment / KEMs.
  - Recommends NIST FIPS standards: **ML-KEM** (FIPS 203), **ML-DSA** (FIPS 204), **SLH-DSA** (FIPS 205), or supported classical/hybrid configurations.
  - Suggests configuration upgrades for symmetric primitives (e.g. AES-256, SHA-384).

---

## Policy Definitions & Governance

The active policy engine is the deterministic **ECDAT review baseline (v1.0.0)** implemented in `ecdat-backend/ecdat/core/discovery/policies.py`:

| Rule | Check | Outcome |
|---|---|---|
| `CRYPTO-LEGACY-001` | MD5, SHA-1, DES, 3DES/DESEDE, RC4/ARC4 | Fail for observed usage; warning for string-only match |
| `CRYPTO-RSA-001` | RSA key length at least 2048 bits | Pass/fail when known; passing does not confer quantum resistance |
| `PQC-MIGRATION-001` | Quantum-vulnerable public-key primitive | Warning to plan migration to ML-KEM / ML-DSA |
| `CRYPTO-KEY-001` | Private-key marker or parsed private key | Warning to review whether key material belongs in artifact |

Verdicts are **pass**, **fail**, **warn**, and **unknown**.

---

## Configuration Reference

Variables configured in `.env`:

| Variable | Purpose / Default |
|---|---|
| `AUTH_USERNAME` / `AUTH_PASSWORD` | Administrator username and strong password, synchronized at startup |
| `AUTH_USERS` | Optional legacy normal-user imports; prefer the Users screen |
| `SESSION_COOKIE_SECURE` | `false` for localhost HTTP; `true` behind HTTPS |
| `ALLOWED_HOSTS` | Allowed HTTP Host headers: `["localhost","127.0.0.1","backend"]` |
| `CORS_ORIGINS` | Permitted browser origins: `["http://localhost:3000","http://127.0.0.1:3000","http://localhost:5173"]` |
| `BACKEND_PORT` | Published localhost API port: `8000` |
| `FRONTEND_ALT_PORT` | Published localhost UI port: `3000` |
| `EVIDENCE_STORE_PATH` | Storage root path (defaults to `/evidence_store` in container) |
| `ENVIRONMENT` | `production` or `development` |
| `LOG_LEVEL` | `INFO`, `DEBUG`, or `WARNING` |
| `ECDAT_DEBUG` | `true` or `false` |

---

## Native Development

Requirements: Python 3.11+, `uv`, Node.js 20+, and npm.

Use the scripts in [Windows local quick start](#windows-local-quick-start), or the manual equivalents below.

### Manual Cross-Platform Setup

#### Backend

```powershell
cd ecdat-backend
uv sync --extra dev
$env:EVIDENCE_STORE_PATH = "$PWD/evidence_store"
$env:ECDAT_DEBUG = "false"
# Once, before first sign-in (prompts for your password):
# Set AUTH_USERNAME and AUTH_PASSWORD in root .env before starting the API
uv run uvicorn ecdat.apps.api.main:app --host 127.0.0.1 --port 8000 --reload
```

#### Frontend

```powershell
cd ecdat-web
npm ci
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). Vite proxies `/api/v1`, `/health`, and `/ready` to `127.0.0.1:8000`.

---

## API Summary

All active API endpoints operate under `/api/v1`:

| Method and Path | Description |
|---|---|
| `GET /api/v1/session` | Check authentication state and account identity |
| `POST /api/v1/session` | Sign in with username and password |
| `DELETE /api/v1/session` | Sign out and end session |
| `GET /api/v1/admin/users` | Admin-only account list; excludes passwords/session tokens |
| `POST /api/v1/admin/users` | Admin-only normal-user creation |
| `PATCH /api/v1/admin/users/{id}` | Admin-only normal-user password reset or enable/disable |
| `POST /api/v1/uploads` | Submit file scan (`apk`, `exe`, `source`, `library`, `container`) |
| `POST /api/v1/uploads/repository` | Submit public Git repository URL for cloning and scanning |
| `GET /api/v1/uploads` | List saved scans |
| `GET /api/v1/uploads/{id}` | Retrieve scan record, status, and findings |
| `GET /api/v1/uploads/{id}/artifacts/{name}` | Download scan artifacts (`original`, `report`, `findings`, `cbom`, `sarif`, `checksums`) |
| `GET /api/v1/workspace/assets` | Query crypto inventory with pagination, algorithm, and confidence filters |
| `GET /api/v1/workspace/assets/{id}` | Detailed observation inspection with evidence and recommendations |
| `GET /api/v1/workspace/scans` | Scans list for dashboard and inventory overview |
| `GET /api/v1/workspace/policies` | Policy baseline compliance results |
| `GET /api/v1/advisories` | Post-quantum cryptographic migration recommendations |
| `GET /api/v1/workspace/export/{format}` | Aggregate export: `cyclonedx` (JSON), `sarif` (JSON), or `csv` |
| `GET /health` & `GET /ready` | Service health and storage writability probes |

---

## Tests and Verification

```powershell
# Run the full backend test suite
cd ecdat-backend
uv run pytest tests -q

# Run frontend typecheck and production build
cd ../ecdat-web
npm run build
```

Verification on September 27: 177 backend tests passed, with one upstream Starlette/httpx deprecation warning. Frontend production build and lint passed. These checks cover implemented paths, not exhaustive security assurance.


## Storage, recovery and maintenance

Back up the complete evidence volume, including `auth.sqlite3` and all account UUID directories. Stop the backend during filesystem backups so the SQLite database and scan artifacts are consistent. Password resets invalidate sessions; deleting the authentication database does not safely transfer ownership of existing scans. Do not reset volumes to repair login problems.

Use one API process: scan admission and restart recovery remain process-local. Interrupted scans are marked failed and must be resubmitted. There is no automatic retention purge or global disk quota; operators must manage capacity. Original uploads may contain secrets even when report metadata omits them. Never publish evidence or authentication storage.

## Review decisions and retained scope

`review.md` records the supplied cleanup proposal and current disposition. PostgreSQL, Valkey, OPA and the unused worker remain removed. A small SQLite authentication store exists because real accounts and revocation require persistent state. Bounded background scanning remains because it supports the working upload/polling flow. Normalization retains mode/padding metadata; static library matches are not relabeled as proven runtime use.

The CLI's deleted Merkle verifier is no longer advertised. Standard JSON, CycloneDX 1.6, SARIF 2.1.0 and CSV outputs remain. SHA-256 checksums do not imply signed or independently timestamped evidence. Optional decompiler integration present in the code is preserved; a successful static scan is not proof of complete binary coverage or safe runtime behavior.

### Appearance and admin navigation

Account management lives at `/admin/users`; `/admin` and the previous `/users` URL redirect there. Normal users receive an access-denied page and the backend rejects account-management requests. Workspace scanning routes remain unchanged.

Use the sun/moon button on the sign-in screen or header to switch light/dark themes. The initial theme follows your system preference; an explicit choice is saved in this browser and restored before rendering. Light mode uses white surfaces, dark green text, teal actions and distinct risk colors.

### Sign-in shows HTML / API unavailable

The API must be healthy before sign-in works. A reverse-proxy error page is not an authentication response. The frontend now rejects HTML and malformed JSON, and nginx returns JSON for gateway failures.

For Docker, check `docker compose logs --tail 50 backend`. If startup reports that environment passwords must contain 15-128 characters, set a strong `AUTH_PASSWORD` in root `.env` . Any optional `AUTH_USERS` passwords must also meet this requirement. Then run `docker compose up -d --build --force-recreate` and `docker compose ps`. A simple container restart does not reload Compose environment values. Never resolve this by disabling authentication or shortening password validation.

For local use, start both `setup.bat backend` and `setup.bat frontend`, then open port 5173. Do not serve the built files using a generic static server: `/api` requires a backend proxy. Avoid running Docker and the local backend on port 8000 simultaneously. Check `/health` through the frontend when diagnosing connectivity.

`.gitignore` excludes credentials, evidence, SQLite authentication state, dependencies, build outputs, caches, logs and generated browser screenshots. Keep test scripts and lockfiles under version control. Ignore rules do not remove files already tracked; review staged changes for sensitive evidence before committing.

Administrator UI update: admins land on `/admin/users`, where Add user and the account list are shown. Admin frontend URLs redirect there; scan navigation and scan creation controls are reserved for normal-user workspaces. Backend account isolation remains unchanged. The header and login page provide a labeled Light theme / Dark theme toggle. Rebuild the Docker frontend after UI changes.
