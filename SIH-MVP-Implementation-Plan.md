# ECDAT — MVP Implementation Plan

**Product:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)  
**Version:** 1.0 MVP  
**Date:** 17 September 2026  
**Status:** Implementation-ready

---

# 1. Implementation Strategy

## Principle

**Adopt at the edges, build in the middle.**

Use proven open-source collectors where they provide useful detection and concentrate proprietary engineering on:

- canonical asset model
- correlation
- confidence
- risk
- policy
- advisory logic
- evidence
- workflow
- API/UI

The implementation must preserve the MVP's ability to run without paid cloud infrastructure.

---

# 2. Target Architecture

```text
                 ┌─────────────────────────┐
                 │ React + TypeScript UI   │
                 └────────────┬────────────┘
                              │
                         REST / OpenAPI
                              │
                 ┌────────────▼────────────┐
                 │       ECDAT API         │
                 │ FastAPI                 │
                 └────────────┬────────────┘
                              │
        ┌─────────────────────┼────────────────────┐
        │                     │                    │
        ▼                     ▼                    ▼
 Collector Manager       Risk Engine          OPA/Rego
        │                     │                    │
        ▼                     ▼                    ▼
 Evidence Envelope       QARS/Mosca          Policy Results
        │
        ▼
 Normalization Pipeline
 parse → identity → dedupe → correlate → confidence
        │
        ▼
 PostgreSQL + JSONB
        │
        ├── Apache AGE (optional MVP graph)
        ├── Valkey
        └── object/file evidence store
        │
        ▼
 Export Layer
 CycloneDX 1.7 / SARIF / JSON / CSV / PDF
        │
        ▼
 Evidence Layer
 Snapshot → Merkle → RFC 3161
        │
        ▼
 CLI / CI / API / UI
```

---

# 3. Repository Structure

```text
ecdat/
├── apps/
│   ├── api/
│   ├── worker/
│   ├── web/
│   └── cli/
├── collectors/
│   ├── source/
│   │   ├── java/
│   │   └── python/
│   ├── dependency/
│   ├── container/
│   ├── binary/
│   └── network/
├── core/
│   ├── model/
│   ├── identity/
│   ├── normalization/
│   ├── correlation/
│   ├── confidence/
│   ├── risk/
│   ├── policy/
│   ├── advisory/
│   └── evidence/
├── integrations/
│   ├── cyclonedx/
│   ├── sarif/
│   ├── jira/
│   ├── service-now/
│   ├── openproject/
│   ├── kms/
│   └── tsa/
├── policies/
│   ├── cnsa/
│   ├── nist/
│   ├── fips/
│   └── customer/
├── benchmarks/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── corpus/
│   ├── security/
│   └── performance/
├── deploy/
│   ├── docker-compose/
│   └── k8s/
└── docs/
```

---

# 4. Technology Selection

| Layer | MVP technology | Alternative |
|---|---|---|
| Source analysis | Python + Tree-sitter | language-native parsers |
| Java crypto | sonar-cryptography integration | custom detector |
| Python crypto | sonar-cryptography + AST rules | custom detector |
| Dependency | native parsers + OSV-Scanner where useful | custom resolvers |
| Container | cbomkit-theia | custom scanner |
| Binary | LIEF + pyelftools | custom signatures |
| API | FastAPI | Go HTTP service |
| Workers | Python/Go processes | direct synchronous execution |
| Database | PostgreSQL 16 | SQLite only for unit tests |
| Graph | Apache AGE | Neo4j Community/Enterprise adapter |
| Queue | Valkey | NATS |
| Policy | OPA/Rego | embedded policy evaluation only for tests |
| Risk | Python + NumPy | pure Python fallback |
| AI | Ollama/vLLM | disabled |
| Secrets | OpenBao | customer KMS |
| Object storage | local filesystem | S3-compatible OSS |
| Frontend | React + TypeScript | — |
| CI | GitHub/GitLab/Jenkins CLI integration | — |
| Packaging | Docker Compose | k3s/Kubernetes |
| Monitoring | Prometheus/Grafana | cloud monitoring |
| Logs | Loki | customer SIEM |
| Evidence timestamp | RFC 3161 | customer-hosted TSA |

---

# 5. Service Boundaries

## API

Responsibilities:
- authentication/authorization
- scan creation
- scan status
- asset queries
- finding queries
- policy execution
- export requests
- audit queries

Must not directly execute arbitrary collectors inside the API process.

## Worker

Responsibilities:
- execute isolated collectors
- process evidence
- run normalization
- execute risk/policy jobs
- generate exports

## Collector

Each collector:
- has version
- has declared capabilities
- accepts a scoped input
- emits canonical Evidence Envelope
- cannot directly mutate business tables
- cannot access unrelated tenant data
- is resource-limited

---

# 6. Evidence Envelope

Proposed structure:

```json
{
  "schema_version": "1.0",
  "collector": {
    "name": "java-source",
    "version": "1.0.0"
  },
  "run": {
    "id": "scan-...",
    "started_at": "...",
    "input_revision": "..."
  },
  "tenant_id": "...",
  "source": {
    "repository": "...",
    "path": "...",
    "line": 142
  },
  "observation": {
    "type": "crypto-api-use",
    "algorithm": "RSA",
    "key_size": 2048
  },
  "confidence": "confirmed",
  "evidence": {
    "fingerprint": "sha256:..."
  }
}
```

Never place raw secrets in the envelope.

---

# 7. Database Model

Core PostgreSQL tables:

```text
tenants
repositories
scans
collectors
assets
occurrences
evidence
components
relationships
risk_assessments
risk_profiles
policy_packs
policy_rules
policy_results
advisories
exemptions
snapshots
audit_events
```

Every tenant-owned table must contain a tenant boundary.

Use JSONB for collector-specific evidence, but promote frequently queried fields to typed columns.

---

# 8. Asset Identity

Implement deterministic identity resolution.

### Algorithm

```text
1. Validate evidence
2. Normalize algorithm/name/configuration
3. Generate identity candidates
4. Match exact stable identifiers
5. Match contextual identifiers
6. Calculate correlation confidence
7. Merge only when matching rules permit
8. Preserve all evidence records
```

Never merge solely because two findings have the same algorithm name.

---

# 9. Source Scanner Implementation

## Java

Detect:
- `javax.crypto`
- `java.security`
- JCA/JCE primitives
- BouncyCastle APIs

Output:
- algorithm
- provider
- operation
- key size/curve if statically determinable
- source location

## Python

Detect:
- `cryptography`
- algorithm classes
- serialization APIs
- key-loading APIs
- signing/encryption APIs

Tree-sitter supplies syntax structure.

AST rules should avoid simplistic regex-only detection.

---

# 10. Dependency Scanner

Build package adapters:

```text
NPM
PyPI
Maven
Go Modules
```

Each adapter resolves:

```text
package
version
direct/transitive
dependency path
known crypto capability
advisory metadata
```

Important logic:

```text
dependency contains crypto
        ≠
application uses crypto
```

Therefore dependency findings initially have evidence type `capability` unless actual use is proven.

---

# 11. Container Scanner

Wrap cbomkit-theia.

For every layer:
- preserve layer identity
- collect certificate metadata
- inspect known crypto configuration
- fingerprint potential secrets
- associate evidence with image digest

Do not store secret contents.

---

# 12. Deterministic Rules Engine

Rules are YAML/JSON/OPA-compatible metadata plus implementation logic.

Example:

```yaml
id: JAVA-RSA-001
version: "1.0"
name: RSA-2048-signature
severity: policy-dependent
confidence: confirmed
conditions:
  language: java
  api: Signature
  algorithm: RSA
  key_size: 2048
```

Every finding references its producing rule.

Rules are versioned and immutable once used in a scan.

---

# 13. Risk Engine

## Mosca

Inputs:

```text
X = data confidentiality lifetime
Y = migration duration
Z = scenario range
```

Evaluate:

```text
X + Y > Z
```

Store:
- inputs
- scenario
- result
- assumptions
- profile version

## QARS

Recommended implementation:

```text
temporal_component
sensitivity_component
exposure_component

QARS =
  Wt * temporal +
  Ws * sensitivity +
  We * exposure
```

Normalize to `0.0–1.0`.

Do not silently incorporate criticality.

---

# 14. Policy Engine

OPA runs as a sidecar/process.

Input:

```json
{
  "asset": {},
  "component": {},
  "risk": {},
  "context": {}
}
```

Output:

```json
{
  "policy": "customer-baseline",
  "rule": "RSA-MIN-001",
  "verdict": "fail",
  "property": "key_size",
  "value": 2048
}
```

Policy packs are versioned bundles.

---

# 15. Advisory Engine

Use a structured mapping database.

```text
primitive
  -> use case
  -> replacement family
  -> parameter options
  -> security level
  -> size
  -> latency class
  -> transition guidance
  -> source reference
```

Do not put advisory logic directly into UI code.

---

# 16. LLM Integration

LLM is disabled by default.

Provider interface:

```text
LLMProvider
 ├── Ollama
 ├── vLLM
 └── Bedrock
```

LLM output:

```text
unconfirmed
```

Store:
- provider
- model
- model version
- prompt version
- input hash
- output
- timestamp

No LLM output may directly create a compliance pass.

---

# 17. Evidence Implementation

Canonical snapshot generation must be deterministic.

```text
sort entities
sort relationships
normalize timestamps where appropriate
serialize canonical JSON
hash snapshot
construct Merkle tree
timestamp root using RFC 3161
```

Offline verifier:

```bash
ecdat verify evidence-pack.zip
```

It must verify:
- snapshot hash
- Merkle path
- root
- TSA token
- policy/rule versions
- provenance

---

# 18. CI Gate

CLI returns:

```text
0 = pass
1 = policy violation
2 = execution/configuration error
3 = unsupported/indeterminate condition requiring attention
```

The exact exit-code contract must be documented and stable.

Baseline mechanism:

```text
existing finding + unchanged fingerprint = baseline
new finding = gate candidate
```

Exemptions require:
- reason
- owner
- created_at
- expiry
- scope

Expired exemptions must fail or warn according to policy.

---

# 19. Frontend

Pages:

```text
/login
/dashboard
/scans
/scans/:id
/assets
/assets/:id
/findings
/policies
/advisories
/graph
/evidence
/audit
/settings
```

Use server-side pagination.

Avoid loading the full 100k asset estate into the browser.

---

# 20. API Contract

Use OpenAPI as the source of truth.

Minimum:

```text
POST /api/v1/scans
GET  /api/v1/scans/{id}

GET  /api/v1/assets
GET  /api/v1/assets/{id}
GET  /api/v1/findings

GET  /api/v1/policies
POST /api/v1/policies/evaluate

GET  /api/v1/risk
GET  /api/v1/advisories

POST /api/v1/exports
POST /api/v1/snapshots
GET  /api/v1/audit
```

API schemas must use explicit versioning.

---

# 21. Security Architecture

## Collector sandbox

Each collector:
- separate process/container
- CPU limit
- memory limit
- execution timeout
- read-only input mount
- restricted filesystem
- no arbitrary network egress

## Secrets

ECDAT must:
- never store secret values
- redact secrets from logs
- fingerprint where necessary
- zero/clear sensitive buffers where practical
- scan its own logs in security tests

## Tenant isolation

Enforce:
- tenant-scoped queries
- tenant-aware object paths
- authorization at API layer
- database-level protections where practical

---

# 22. Testing Strategy

## Unit

- parsers
- rules
- identity
- normalization
- QARS
- Mosca
- policies
- advisory mappings
- Merkle construction

## Integration

- collector → evidence → database
- scan → CBOM
- scan → policy
- scan → CI gate
- snapshot → verifier

## Security

- malicious repository
- malformed binary
- malicious container
- oversized file
- path traversal
- secret leakage
- cross-tenant access
- collector escape
- API authorization

## Benchmark

Create a hand-labelled corpus containing:
- known crypto uses
- false positives
- wrappers
- aliases
- unused implementations
- dependency-only crypto
- hardcoded key indicators

Publish recall/precision by supported language.

---

# 23. Development Phases

## Phase 0 — Foundation and Validation

Duration: ~2–4 weeks

Deliver:
- benchmark corpus
- architecture decisions
- repository skeleton
- database schema
- evidence envelope
- collector interface
- CycloneDX SDK validation
- security threat model

Exit:
- benchmark baseline
- canonical model approved
- technology decisions frozen

---

## Phase 1 — Core Discovery

Duration: ~6–8 weeks

Deliver:
- Java scanner
- Python scanner
- dependency scanners
- PostgreSQL
- normalization
- identity
- correlation
- CLI
- REST API
- CycloneDX 1.7

Exit:

```text
ecdat scan repo
```

produces a valid CBOM with provenance.

---

## Phase 2 — Trust and Breadth

Duration: ~6–8 weeks

Deliver:
- container/filesystem
- deterministic rules
- confidence
- deduplication
- asset explorer
- audit events
- scan governance framework
- optional graph

Exit:
- repeatable weekly scans
- measured false positives
- traceability from finding to evidence

---

## Phase 3 — Risk and Policy

Duration: ~6–8 weeks

Deliver:
- Mosca
- QARS
- OPA
- policy packs
- advisory engine
- CI gate
- baseline
- exemptions

Exit:
- risk results reproducible
- policy results traceable
- architect review completed

---

## Phase 4 — Evidence and MVP Hardening

Duration: ~4–6 weeks

Deliver:
- immutable snapshots
- Merkle
- RFC 3161
- offline verifier
- evidence pack
- PDF
- security hardening
- performance tests
- deployment package

Exit:
- complete MVP release candidate

---

## Phase 5 — Enterprise Extensions

Deliver after core MVP:
- network TLS
- binary analysis
- KMS/HSM
- certificates
- LLM
- SSO/RBAC
- ticketing
- Kubernetes
- air-gapped bundle
- scale hardening

---

# 24. Free MVP Deployment

`docker-compose.yml` should run:

```text
ecdat-api
ecdat-worker
ecdat-ui
postgres
opa
valkey
```

Optional profiles:

```text
--profile ai
--profile graph
--profile monitoring
--profile secrets
```

This keeps optional components out of the default installation.

---

# 25. Observability

Use:

- Prometheus metrics
- Grafana dashboards
- Loki logs

Minimum metrics:

```text
scan_duration_seconds
collector_duration_seconds
collector_failures_total
findings_total
confirmed_findings_total
policy_failures_total
cbom_exports_total
queue_depth
api_latency
```

---

# 26. Performance Targets

Do not claim the full PRD scale until measured.

Initial MVP targets:

- incremental scan of 100k LoC: documented benchmark
- API p95: <500 ms for common paginated queries
- UI initial data: <2 seconds on representative dataset
- collector crash isolation
- bounded memory usage

Later GA target from PRD:
- 100k assets
- 5k repositories
- 250k certificates
- full-estate rescan within 24h
- dashboard p95 <2s
- incremental 500k-LoC scan <5 min

---

# 27. Engineering Gaps and Decisions

## Architecture gaps

1. Exact event/job queue semantics.
2. PostgreSQL partitioning strategy.
3. Evidence object retention policy.
4. Apache AGE adoption threshold.
5. Multi-tenant isolation mechanism.
6. Authentication provider for local deployment.
7. API rate limits.
8. Worker retry/dead-letter semantics.

## Logic gaps

1. Static implementation vs actual use.
2. Dependency capability vs active usage.
3. Identity collision rules.
4. Confidence promotion rules.
5. X/Y risk default ownership.
6. QARS calibration.
7. Criticality independence.
8. Exposure derivation.
9. Policy source/version lifecycle.
10. Advisory confidence and standard status.
11. LLM confirmation workflow.
12. Indeterminate/unsupported semantics.
13. Partial scan semantics.
14. Exemption precedence.
15. Historical reproducibility.

---

# 28. Recommended Initial Defaults

These are product defaults, not authoritative security standards:

```text
AI: disabled
Network scanning: disabled
Cloud connectors: disabled
Graph: optional
Object storage: local
Queue: Valkey
Database: PostgreSQL
Policy: OPA
Deployment: Docker Compose
Evidence: filesystem + PostgreSQL metadata
TSA: configurable
```

This maximizes free/self-hosted operation.

---

# 29. Definition of Done

A feature is not complete until it has:

- implementation
- API contract
- UI representation where applicable
- unit tests
- integration test
- security test where relevant
- provenance
- versioning
- audit event
- documentation
- benchmark impact assessment
- failure/unknown behavior

---

# 30. MVP Exit Checklist

```text
[ ] Java source scanning
[ ] Python source scanning
[ ] Dependency scanning
[ ] Container/filesystem scanning
[ ] Canonical model
[ ] Evidence envelope
[ ] Stable identity
[ ] Deduplication
[ ] Confidence
[ ] Deterministic rules
[ ] PostgreSQL
[ ] OPA/Rego
[ ] Mosca scenarios
[ ] QARS
[ ] Advisory engine
[ ] CycloneDX 1.7
[ ] SARIF
[ ] CSV/JSON
[ ] CLI
[ ] REST API
[ ] React dashboard
[ ] Asset explorer
[ ] CI gate
[ ] Baseline/exemptions
[ ] Audit log
[ ] Merkle snapshots
[ ] RFC 3161
[ ] Offline verifier
[ ] Docker Compose
[ ] Security tests
[ ] Benchmark corpus
[ ] Measured recall/precision
[ ] Reproducibility tests
[ ] Documentation
```

---

# 31. Post-MVP Roadmap

After the MVP proves the core workflow:

```text
MVP
 |
 +-- Network TLS
 |
 +-- Binary/ELF/PE
 |
 +-- Cloud KMS/HSM
 |
 +-- Certificate estate
 |
 +-- Graph/blast radius
 |
 +-- Local LLM
 |
 +-- SSO/RBAC
 |
 +-- Ticketing
 |
 +-- Kubernetes
 |
 +-- Air-gapped bundle
 |
 +-- 100k asset scale
```

The original implementation plan's five-phase sequence remains useful, but this version makes the free/self-hosted path explicit and moves enterprise integrations behind stable interfaces.


---

# 31. Detailed Gap-Resolution Implementation

This section converts every previously open architecture and logic gap into concrete implementation behavior.

## 31.1 Job/Event State Machine

Implement the job state machine in PostgreSQL.

### Tables

```text
jobs
job_attempts
job_events
dead_letter_events
```

### Claiming

Workers claim jobs transactionally using row locking and lease timestamps.

Required behavior:

```text
QUEUED
 -> CLAIMED with lease_until
 -> RUNNING
```

If `lease_until` expires:

```text
RUNNING -> QUEUED
```

unless the worker has reached the maximum attempts.

### Idempotency

Every job gets an `idempotency_key`.

Workers must use upsert or unique constraints so retries cannot duplicate:
- findings;
- policy results;
- advisory records;
- exports;
- snapshots.

Valkey can notify workers of new jobs but recovery must work when Valkey is unavailable.

---

## 31.2 PostgreSQL Partitioning Implementation

Create monthly partitions for:
- `audit_events`;
- `evidence`;
- `scan_events`;
- `job_events`.

Core asset tables remain unpartitioned initially.

Add maintenance automation to:
- create the next partition;
- warn before a partition boundary;
- archive/delete data according to retention policy;
- respect legal hold.

Partitioning must be benchmark-driven rather than speculative.

---

## 31.3 Evidence Storage Implementation

Use PostgreSQL for structured evidence metadata and a local filesystem/S3-compatible store for larger payloads.

Example:

```text
evidence
- id
- tenant_id
- occurrence_id
- content_hash
- content_type
- size
- storage_uri
- retention_until
- retention_hold
- collector_version
```

Secret payloads are not stored.

Evidence access must be authorized and audited.

---

## 31.4 Apache AGE Decision Gate

Implement a feature flag:

```text
GRAPH_BACKEND=postgresql|age
```

Default:

```text
postgresql
```

Run graph benchmark jobs during Phase 2.

Enable AGE when:
- graph node/edge thresholds are exceeded;
- relational traversal misses approved latency;
- graph UI requires persistent traversal performance.

This lets the MVP stay operational with PostgreSQL alone.

---

## 31.5 Tenant Isolation Implementation

### API

Inject `tenant_id` from the authenticated identity.

Never accept an arbitrary tenant ID from the browser without authorization.

### Database

Set the tenant context for each transaction/session and enforce RLS.

### Object storage

Use:

```text
/{tenant_id}/{artifact_type}/{object_id}
```

and authorize every object read.

### Tests

Required cross-tenant tests:
- read;
- update;
- delete;
- export;
- evidence download;
- job inspection;
- graph traversal.

---

## 31.6 Local Authentication

Package Keycloak in an optional Docker Compose profile:

```text
docker compose --profile auth up
```

Production deployments may connect Keycloak to customer OIDC/SAML IdPs.

Development may use a local username/password provider.

All identity implementations must expose the same internal principal model:

```text
subject_id
tenant_id
roles
groups
```

---

## 31.7 API Rate Limiting

Implement token bucket at:
- user;
- token/client;
- tenant;
- expensive endpoint.

Expensive endpoints include:
- scan creation;
- exports;
- graph traversal;
- large evidence downloads.

Return HTTP 429 plus `Retry-After`.

Metrics:

```text
api_rate_limit_hits_total
```

---

## 31.8 Retry and Dead-Letter Processing

Create error classes:

```text
RETRYABLE
NON_RETRYABLE
SECURITY
CONFIGURATION
UNSUPPORTED
```

Security/configuration errors should normally go directly to final failure rather than being retried repeatedly.

Dead-letter UI must show:
- job;
- scan;
- tenant;
- attempts;
- error;
- last worker;
- input hash;
- retry history.

---

# 32. Logic Implementation

## 32.1 Observation Taxonomy

Every crypto observation gets:

```text
observation_type
usage_evidence
confidence
```

Example:

```json
{
  "observation_type": "algorithm_use",
  "usage_evidence": "static",
  "confidence": "confirmed"
}
```

---

## 32.2 Dependency Evidence Levels

Implement:

```text
CAPABILITY
IMPORT
STATIC_USE
RUNTIME_USE
```

Policy and risk rules may treat these differently.

Example default:

```text
CAPABILITY
  -> inventory only

STATIC_USE
  -> risk eligible

RUNTIME_USE
  -> risk eligible + runtime evidence

UNKNOWN
  -> surfaced, not silently excluded
```

---

## 32.3 Identity Resolver

Create a standalone service/module:

```text
IdentityResolver.resolve(observation)
```

It returns:

```text
asset_id
match_type
match_confidence
possible_duplicates[]
```

Store the identity decision as evidence so historical scans can be reproduced.

---

## 32.4 Confidence Engine

Create a deterministic evidence scoring/decision table.

Example:

```text
authoritative external observation + exact resource
    -> CONFIRMED

deterministic AST rule + exact location
    -> CONFIRMED

multiple independent supporting collectors
    -> CONFIRMED if rules permit

single heuristic
    -> PROBABLE

LLM hypothesis
    -> UNCONFIRMED
```

The exact promotion rules must be stored in a versioned configuration.

---

## 32.5 Mosca Inputs

Create tables:

```text
risk_profiles
x_assumptions
y_assumptions
z_scenarios
```

Each risk assessment references these records.

### X configuration hierarchy

```text
customer asset class
-> customer data metadata
-> policy default
-> product generic default
```

### Y configuration hierarchy

```text
asset class
-> migration complexity band
-> customer override
```

The UI must show the source and assumption behind X/Y.

---

## 32.6 QARS Profile

Create:

```text
risk_profiles
```

Example:

```json
{
  "version": "default-v1",
  "weights": {
    "temporal": 0.333333,
    "sensitivity": 0.333333,
    "exposure": 0.333333
  }
}
```

Every assessment stores `risk_profile_version`.

Override workflow:

```text
score
 -> human override
 -> reason
 -> audit event
```

---

## 32.7 Exposure Resolver

Create:

```text
ExposureResolver
```

Inputs:
- scan authorization;
- allowlist;
- segment metadata;
- operator-supplied classification.

Output:

```text
internal
external
dmz
unknown
```

The resolver must retain the evidence behind the classification.

---

## 32.8 Policy Version Manager

Policy bundles are content-addressed and immutable.

Deployment:

```text
policy bundle
 -> checksum
 -> version
 -> source metadata
 -> activation
```

Activation creates an audit event.

Changing the active policy never rewrites historical results.

---

## 32.9 Advisory Registry

Create tables:

```text
advisory_families
advisory_variants
advisory_sources
```

Each variant contains:

```text
family
parameter_set
security_level
public_key_size
signature_size
ciphertext_size
latency_class
standard_status
production_recommendation
source_reference
```

---

## 32.10 LLM Review Workflow

Create:

```text
llm_hypotheses
llm_reviews
```

States:

```text
UNCONFIRMED
ACCEPTED
REJECTED
SUPERSEDED
```

Only `ACCEPTED` human-reviewed or deterministically verified hypotheses may influence supported downstream logic, and the original LLM provenance remains stored.

---

## 32.11 Unknown/Unsupported/Indeterminate

Add explicit fields:

```text
analysis_status
analysis_reason
```

Allowed status values:

```text
OBSERVED
NOT_OBSERVED
UNKNOWN
INDETERMINATE
UNSUPPORTED
```

UI must expose these as different states.

---

## 32.12 Partial Scan Handling

Every collector writes an execution result.

The scan aggregator computes:

```text
COMPLETE
PARTIAL
FAILED
CANCELLED
```

Required collector failures are recorded as blocking for `COMPLETE`.

Exports must include a scan completeness statement.

---

## 32.13 Exemption Engine

Evaluation order:

```text
raw finding
   ↓
policy rule
   ↓
policy result
   ↓
active exemption lookup
   ↓
gate outcome
```

Exemptions never alter policy source data.

Expired exemptions never match.

Every exemption use creates an audit event.

---

## 32.14 Conflict Resolution

Collector findings remain separate until normalized.

Build a conflict record:

```text
conflict_id
asset_id
evidence_ids[]
conflict_type
resolution_state
resolution_reason
resolved_by
resolved_at
```

No automatic destructive overwrite.

---

## 32.15 Historical Replay

Build:

```text
ecdat replay --snapshot <id>
```

The replay command:
1. loads the snapshot evidence;
2. loads referenced rule/policy/risk versions;
3. recomputes derived outputs;
4. verifies hashes;
5. reports differences.

Historical evidence must not depend on the availability of the original repository.

---

# 33. Certificate Integration

Initial certificate interface:

```text
CertificateProvider
```

Methods:

```text
list_certificates()
get_certificate(id)
```

MVP adapters:
- REST
- JSON
- CSV

Post-MVP:
- Keyfactor
- Venafi
- additional PKI systems

ECDAT does not perform certificate issuance/revocation.

---

# 34. Auditor Evidence Pack Implementation

Create an evidence pack builder with deterministic file ordering.

```text
EvidencePackBuilder
  -> scope
  -> methodology
  -> inventory
  -> policy results
  -> exceptions
  -> risk
  -> advisories
  -> provenance
  -> CBOM
  -> snapshot
  -> Merkle proof
  -> TSA token
  -> audit log
```

Hash the canonical manifest.

Offline verifier checks:
- manifest hash;
- file hashes;
- Merkle root;
- Merkle paths;
- RFC 3161 token;
- referenced versions.

---

# 35. CycloneDX Adapter Architecture

Create interfaces:

```text
CycloneDXExporter
```

Implement:

```text
CycloneDX17Exporter
CycloneDX16Exporter
```

Future:

```text
CycloneDX2Exporter
```

The domain model must not import CycloneDX-specific database concepts.

---

# 36. Benchmark Engineering

Create:

```text
benchmarks/
  java/
  python/
  npm/
  pypi/
  maven/
  gomod/
  containers/
```

Each fixture includes:
- ground truth;
- expected findings;
- expected location;
- expected confidence;
- expected status.

Benchmark report:

```text
language
asset class
true positives
false positives
false negatives
precision
recall
unsupported cases
indeterminate cases
```

Supported-language claims are generated from benchmark results, not from parser availability.

---

# 37. MVP Scale Benchmark

Build a synthetic scale dataset:

```text
10,000 assets
500 repositories
25,000 certificates
10 concurrent scans
```

Measure:
- API latency;
- worker throughput;
- database query latency;
- queue depth;
- memory;
- storage growth;
- graph query performance if AGE is enabled.

Do not publish GA scale claims until the measurements are repeatable.

---

# 38. Implementation Order for Gap Closure

```text
Phase 0
  ├── canonical model
  ├── tenant model
  ├── job model
  ├── evidence model
  ├── identity rules
  ├── confidence rules
  ├── benchmark definition
  └── security model

Phase 1
  ├── PostgreSQL
  ├── worker state machine
  ├── source/dependency collectors
  ├── normalization
  ├── CycloneDX adapters
  └── API/CLI

Phase 2
  ├── retention
  ├── RLS
  ├── Keycloak
  ├── deterministic rules
  ├── conflict model
  ├── partial-scan model
  ├── container scanning
  └── graph benchmark

Phase 3
  ├── X/Y risk configuration
  ├── Z scenarios
  ├── QARS profiles
  ├── OPA versions
  ├── exemptions
  ├── advisory registry
  └── CI gate

Phase 4
  ├── Merkle
  ├── RFC3161
  ├── replay
  ├── auditor pack
  ├── evidence retention jobs
  └── scale benchmark

Phase 5
  ├── AGE if justified
  ├── network
  ├── binary
  ├── KMS/HSM
  ├── certificate adapters
  ├── LLM
  └── enterprise integrations
```

---

# 39. Definition of Done — Updated

A feature is incomplete unless:
- schema exists;
- API contract exists where applicable;
- provenance exists;
- versioning exists;
- audit behavior exists;
- failure semantics exist;
- unit tests exist;
- integration tests exist;
- security tests exist where applicable;
- benchmark impact is recorded;
- unknown/unsupported behavior is explicit;
- historical behavior is reproducible where the feature affects analysis.

---

# 40. Final Engineering Decisions

The MVP should be implemented with these locked defaults:

```text
System of record: PostgreSQL
Queue acceleration: Valkey
Tenant isolation: PostgreSQL RLS + application authorization
Local identity: Keycloak
Graph: PostgreSQL first, AGE by measured threshold
AI: disabled by default; Ollama/vLLM optional
Secrets: OpenBao optional
Object evidence: filesystem/S3-compatible store
Policy: OPA/Rego
Risk: Python/NumPy
Evidence: Merkle + RFC 3161
Deployment: Docker Compose
Kubernetes: post-MVP
```

The implementation should favor deterministic behavior over convenience and should never convert absence of evidence into a positive security conclusion.
