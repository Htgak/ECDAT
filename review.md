# Review disposition - September 27, 2026

The twelve supplied attachments are byte-identical copies of the proposal preserved below. Recommendations were checked against the current implementation; the proposal is not an authoritative description of the code.

| Recommendation | Disposition |
|---|---|
| Remove PostgreSQL, Valkey, OPA, workers and dead database routers | Already removed in the supplied code. Removed the remaining unreferenced SQL audit service and stale dependency-lock entries. Compose retains two services. |
| Fix CurrentUser database dependency | Already DB-free; the real issue was anonymous and forged guest identity access. Replaced it with verified account sessions. |
| Remove login / do not build auth | Rejected: the user's explicit request requires proper prototype authentication. Added password accounts, server-revocable sessions, throttling and per-user scan authorization. |
| Simplify confidence | Keep observed/indicator distinctions. Exact static/library matches do not prove runtime usage; do not rename them to confirmed merely for presentation. |
| Replace normalization with a small alias dict | Retain the existing tested normalizer because it preserves modes and padding. The separate normalization pipeline was already removed. Fixed CLI deduplication to retain distinct source locations/configurations. |
| Remove audit/proof UI | Already removed from active navigation. Removed the leftover broken CLI Merkle verifier; preserved checksums and standard exports. |
| Make uploads synchronous | Rejected: bounded BackgroundTasks and polling already serve the active workflow. No distributed queue was added. |
| Keep JSON/CycloneDX/SARIF/CSV | Preserved and tested, including authenticated aggregate exports and account isolation. |
| Keep policies/evaluate because the UI calls it | Current UI calls GET /workspace/policies. The proposal's claim was stale; the active deterministic rules remain. |
| Verify the end-to-end demo | Full backend suite now covers the actual retained path, including authentication. Browser verification uses isolated temporary storage rather than seeding live data. See handoff.md for results. |

Authentication uses Python's built-in SQLite for accounts/session digests, not an external DB service or ORM. No default credentials or public registration are shipped. Configure the administrator through root `.env` , then create normal accounts through the admin-only Users screen. Administrator permissions do not grant access to other users' scan data. See the README for local batch commands and the latest handoff for the 176-test and browser verification results. Guest cleanup endpoints and tab-close deletion promises are removed; existing artifacts are preserved.

Current gateway follow-up: HTML login failures were traced to backend startup rejecting weak environment passwords. UI parsing and nginx error responses were corrected without relaxing authentication. See README troubleshooting and the latest handoff for verification and deployment status.

---

## Original proposal (historical input, not current instructions)

# ECDAT Codebase Review — Over-Engineering Cleanup

## Context

ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) is a scan → catalogue →
assess → recommend → export pipeline for cryptographic inventory and PQC migration
planning. The codebase has accumulated enterprise-scale infrastructure that the
active, demonstrated workflow does not use. This review identifies what to remove,
what to simplify, and what to keep — and lays out a safe execution order.

**Guiding principle:** Delete infrastructure that has no active role in the
demonstrated end-to-end workflow. Simplify functionality that's useful but
over-built. Do not delete anything without first verifying it's actually unused.

**The target end-to-end demo path** (this must keep working after every phase):

```
Open app → Upload repository → Scan → See crypto inventory →
See risk assessment → See PQC recommendation → Export CBOM/SARIF/CSV
```

---

## Phase 0 status: ✅ COMPLETE — verified, safe to proceed to Phase 1

Database dependency verification has been run against the actual router code.
Result: **the active demo path is 100% filesystem-backed.** PostgreSQL is
confirmed safe to remove, with one blocker to fix first.

**Active routers (frontend-called, no DB dependency):** `uploads.py`,
`workspace.py`, `advisories.py`, `access.py`.

**Confirmed dead routers (DB-backed, zero frontend callers — delete in Phase 1/3):**
`scans.py`, `assets.py`, `findings.py`, `risk.py`, `snapshots.py`, `audit.py`,
`auth.py`, `admin.py`, and `exports.py` (both its endpoints already return 410
or redirect). `policies.py` is mixed: its `GET /policies` (DB-backed) is dead
and should be removed, but `POST /policies/evaluate` is the live,
filesystem-backed endpoint the frontend actually uses — keep it, and drop its
unused `db` parameter.

### ⚠️ Blocker to fix before touching PostgreSQL

`workspace.py` — the router backing every active frontend call — depends on
`CurrentUser`, which resolves through `get_current_user()` in
`ecdat/apps/api/auth/dependencies.py`. That dependency injects an
`AsyncSession` (`get_db`) even though, in the demo's default no-token
configuration, it never actually queries it (it short-circuits to
`_DEFAULT_DEV_USER`). Because FastAPI's DI still constructs the session, the
Postgres connection pool must exist at startup — so removing the DB now would
break app startup even though no query would ever run.

**Fix required, before Phase 3:** replace `CurrentUser` in `workspace.py` (and
any other active router using it) with a dependency that doesn't touch
`get_db` at all:

```python
# Simplified user resolution — no database needed
async def get_workspace_user(request: Request) -> SimpleUser:
    """Return the workspace user. No database lookup."""
    settings = get_settings()
    if not settings.workspace_access_token:
        return _DEFAULT_USER  # open access
    token = _extract_token(request)
    if token and token == settings.workspace_access_token:
        return _DEFAULT_USER
    raise HTTPException(401, "Authentication required.")
```

Swap every `CurrentUser` usage on the active path to this (or equivalent)
before deleting anything in Phase 3.

---

**The target architecture after cleanup:**

```
                React Frontend
                      |
                   FastAPI
                      |
      ┌───────────────┼────────────────┐
      ▼               ▼                ▼
  Upload/Scan     Assessment       Policies
      │               │                │
      └───────────────┼────────────────┘
                       ▼
                  Advisories
                       │
                       ▼
             Workspace Storage
             JSON / CSV / files
                       │
                       ▼
          CycloneDX / SARIF / CSV
```

---

## Findings, item by item

| # | Component | Verdict | Why |
|---|-----------|---------|-----|
| 7 | Background worker (`worker/main.py`, `worker/handlers.py`) | **Remove** | Active upload pipeline scans inline; this Postgres-queue daemon (`FOR UPDATE SKIP LOCKED`) is unused legacy. |
| 8 | OPA sidecar (`policy/opa_client.py`, `policy/evaluator.py`, `policies/*.rego`) | **Remove** | `policies.py` (plain Python, ~100 lines, 4 rules) is the actual enforcement engine. |
| 9 | Valkey (Redis) | **Remove** | Only existed to back the worker queue (#7). Nothing else touches it. |
| 10 | PostgreSQL + Alembic + 10 ORM models + `database.py` | **Remove — but verify first** | Active workspace is filesystem/JSON-backed; DB inventory is empty. **Do not delete until you've confirmed no live route depends on it** (see Phase 0 below). |
| 11 | Correlation engine (`correlation/engine.py`) | **Remove** | Cross-scan pattern detection is a continuous-monitoring feature; the demo is single-pass. |
| 12 | Confidence scoring engine (`confidence/engine.py`) | **Simplify, don't remove** | The *concept* (confirmed vs. inferred) is useful to judges. Replace the module with a single field. |
| 13 | Normalization pipeline (`normalization/algorithms.py`, `normalization/pipeline.py`) | **Simplify, don't remove** | ~30 algorithms don't need a two-file pipeline. A dict + one function is sufficient. |
| 14 | Audit Page (`AuditPage.tsx`) | **Remove** | Tied to Merkle/sealed-snapshot system, which is itself out of scope. |
| 15 | Export Center "proof verifier" section | **Remove that section only** | Keep CycloneDX/SARIF/CSV export — that's the real deliverable. Drop only the Merkle-proof verification UI. |
| 16 | WorkspaceAccess login gate | **Simplify** | No real auth sits behind it. Route directly to the workspace/dashboard for the demo. |
| 17 | Empty `components/ai/`, `core/ai/` | **Remove** | Dead directories, leftover from a removed chatbot feature. Pure cleanup. |

**Keep, unconditionally:** CycloneDX 1.6, SARIF 2.1.0, CSV, and JSON export. These
make the tool read as a real security product rather than a UI mockup.

---

## Execution plan for the agent

### Phase 0 — Verify before touching the database layer ✅ DONE

Verification is complete — see "Phase 0 status" above for the full router
classification. Summary: active path is filesystem-backed; DB removal is
cleared, contingent on one fix:

- [ ] Replace `CurrentUser` in `workspace.py` (and any other active-path
      router that uses it) with the DB-free `get_workspace_user` dependency
      shown above. Do this **before** Phase 3, not as part of it — Phase 3
      assumes it's already done.

### Phase 1 — Remove dead infrastructure

Safe to delete outright (no verification needed beyond confirming no imports
reference them):

- [ ] Dead legacy routers, confirmed zero frontend callers: `scans.py`,
      `assets.py`, `findings.py`, `risk.py`, `snapshots.py`, `audit.py`,
      `auth.py`, `admin.py`, `exports.py`. In `policies.py`, remove only the
      DB-backed `GET /policies` handler — keep `POST /policies/evaluate` and
      drop its unused `db` parameter.
- [ ] `worker/main.py`, `worker/handlers.py`, worker's Dockerfile/service entry
- [ ] `policy/opa_client.py`, `policy/evaluator.py`, `policies/` (Rego files),
      OPA service from `docker-compose.yml`
- [ ] Valkey service + volume from `docker-compose.yml`
- [ ] `correlation/engine.py` and any routes/imports that reference it
- [ ] `AuditPage.tsx` and its route/nav entry in the frontend
- [ ] "Proof verifier" section inside `ExportCenterPage.tsx` (keep the rest of
      the file — CycloneDX/SARIF/CSV export stays)
- [ ] `components/ai/`, `core/ai/` empty directories
- [ ] Merkle tree / RFC3161 timestamping / sealed-snapshot code and any
      Identity Resolver / RLS code confirmed dead in the earlier audit

After each deletion, grep for the removed module's name/import path across the
repo to make sure nothing still references it before moving on.

### Phase 2 — Simplify (keep the concept, cut the architecture)

**Confidence:** replace `confidence/engine.py` + `scoring.py` with a single
typed field on the finding model:
```python
class Finding:
    ...
    confidence: Literal["confirmed", "possible"]
```
Set it inline wherever a finding is created — exact pattern/library match →
`"confirmed"`; heuristic/regex match → `"possible"`. Delete the `confidence/`
module once every call site is updated.

**Normalization:** replace `normalization/algorithms.py` + `pipeline.py` with:
```python
ALGORITHM_ALIASES = {
    "aes_256_gcm": "AES-256-GCM",
    "aes-256-gcm": "AES-256-GCM",
    "aes256gcm": "AES-256-GCM",
    "rsa2048": "RSA-2048",
    # ... remaining ~25 aliases
}

def normalize_algorithm(name: str) -> str:
    key = name.lower().strip()
    return ALGORITHM_ALIASES.get(key, name)
```
Populate `ALGORITHM_ALIASES` from whatever variants the current pipeline
actually handles, then delete the `normalization/` package.

**Login gate:** simplify `WorkspaceAccess.tsx` so the app routes straight to
the workspace/dashboard on load. Don't build real auth for the demo.

**Scanning execution model:** keep it synchronous. Do **not** introduce
`BackgroundTasks`, threads, or any async job model as part of this cleanup —
`POST /upload → save → scan → analyse → return result` is correct for a
hackathon demo. Only revisit this if profiling shows a scan taking long enough
to hit an HTTP timeout, and treat that as a separate, later decision (real job
queue), not a partial fix.

### Phase 3 — Database removal (Phase 0 confirmed safe; requires CurrentUser fix first)

- [ ] Confirm the `CurrentUser` → `get_workspace_user` swap (Phase 0 blocker)
      is complete in `workspace.py` and any other active router. Do not proceed
      until this is done — removing the DB before this fix will break app
      startup even though no query would have run.
- [ ] Remove `alembic/` directory
- [ ] Remove the 10 ORM model files under `core/model/`
- [ ] Remove `database.py` (async session factory)
- [ ] Remove PostgreSQL service from `docker-compose.yml`
- [ ] Update any legacy endpoints that queried these models to either be
      deleted outright or return their already-established `410`/empty response
      without touching the DB

### Phase 4 — Full demo run-through

Run the exact target path end to end after all phases:

```
Open app
  → Upload repository
  → Scan
  → See crypto inventory
  → See risk assessment
  → See PQC recommendation
  → Export CBOM/SARIF/CSV
```

If this works cleanly with no errors and no references to removed modules,
stop. Do not add architecture back in "for completeness" — every remaining box
in the diagram should be answerable with a one-sentence "why."

---

## Notes for the agent

- Do the phases **in order**. Phase 0 exists specifically to prevent deleting
  something the live demo secretly depends on.
- After each deletion, grep the repo for the module's name/import path to
  confirm nothing else references it before moving to the next item.
- Where this review says "simplify," the goal is to preserve the *information*
  (confirmed/possible, canonical algorithm names) while removing the
  *architecture* (multi-file engines/pipelines) built around it.
- If judges/reviewers ask "why does X exist," every remaining component should
  have a truthful one-sentence answer. If Phase 1–3 leaves anything that
  doesn't, flag it for removal too.
