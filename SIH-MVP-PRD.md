# ECDAT — MVP Product Requirements Document

**Product:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)  
**Version:** 1.0 MVP  
**Date:** 17 September 2026  
**Status:** Implementation-ready MVP specification

---

## 1. Product Summary

ECDAT is a self-hosted cryptographic discovery and analysis platform that discovers cryptographic assets across source repositories, dependencies, containers/filesystems and selected artifacts; normalizes findings into an internal canonical model; emits CycloneDX 1.7 CBOMs; evaluates quantum exposure; evaluates configurable policies; provides migration advisories; and produces traceable evidence.

### MVP product principle

> An inventory nobody trusts is worthless.

Every finding must carry provenance, confidence, evidence, collector/version information and a path to human verification.

The MVP deliberately avoids making cloud services, commercial databases, hosted AI, Kubernetes, Jira or ServiceNow mandatory dependencies. Enterprise integrations are adapters.

---

## 2. MVP Goals

### P0 Goals

1. Discover cryptographic usage in Java and Python source repositories.
2. Discover direct and transitive dependencies for npm, PyPI, Maven and Go modules where reliable package metadata is available.
3. Inspect containers/filesystems for certificates, crypto configuration, keystores and key-material indicators without persisting secret values.
4. Normalize all collector output into one version-independent canonical model.
5. Deduplicate discoveries from multiple collectors.
6. Distinguish `implements` from `uses`.
7. Assign `confirmed`, `probable` or `unconfirmed` confidence.
8. Calculate transparent Mosca scenarios and QARS as a tunable prioritization heuristic.
9. Evaluate CBOM findings with OPA/Rego policies.
10. Provide initial policy packs and customer-defined policies.
11. Map vulnerable primitives to NIST-approved replacement families.
12. Export CycloneDX 1.7 CBOM plus JSON, CSV and SARIF; PDF/evidence export is included at the MVP evidence milestone.
13. Provide CLI, REST API and web UI.
14. Provide CI/CD gating with warn-only mode, baselining and expiring exemptions.
15. Maintain append-only audit records.
16. Provide immutable snapshots with Merkle roots and RFC 3161 timestamps.
17. Run entirely self-hosted with free/open-source components.

### P1 / post-core-MVP

- Network TLS profiling with authorization governance.
- Binary/ELF/PE inspection.
- Cloud KMS/HSM connectors.
- Certificate estate correlation.
- Interactive dependency graph.
- Local LLM enrichment.
- SSO/RBAC hardening.
- Jira/ServiceNow/OpenProject integrations.
- Kubernetes/air-gapped production packaging.
- Full 100k-asset scale target.

---

## 3. Non-Goals

ECDAT MVP does not:

- Rotate keys.
- Reissue certificates.
- Rewrite application code.
- Act as a CA, KMS or HSM.
- Instrument live application processes.
- Interrogate OT/ICS controllers deeply.
- Claim an authoritative Q-day date.
- Treat an LLM as an authoritative compliance source.
- Persist raw secret/key values.
- Design scans to evade IDS/IPS.

---

## 4. Personas

| Persona | MVP job |
|---|---|
| Crypto architect | Understand cryptography and provenance |
| CISO | See exposure and trends |
| GRC lead | Produce traceable policy/evidence output |
| AppSec lead | Prevent new weak crypto in CI |
| Developer | Find exact file/line and remediation guidance |
| Network engineer | Control and audit active scans |

---

## 5. MVP Functional Requirements

### 5.1 Discovery

#### D-1 Source scanning — P0

Launch support:
- Java: JCA and BouncyCastle
- Python: pyca/cryptography

Detect:
- API usage
- algorithm instantiation
- key generation
- signature/encryption operations
- hardcoded key-material indicators

Each finding must include:
- repository
- commit/ref
- file
- line/column where available
- collector
- collector version
- detection rule
- confidence
- evidence fingerprint

Coverage must be measured against a hand-labelled benchmark corpus.

#### D-2 Dependency scanning — P0

Support:
- npm
- PyPI
- Maven
- Go modules

Resolve transitive dependencies where package metadata permits.

Model:
`application -> package -> version -> crypto capability`

Dependency presence alone must not automatically imply active cryptographic exposure.

#### D-3 Container/filesystem scanning — P0

Inspect:
- image layers
- X.509 certificates
- openssl.cnf
- java.security
- keystores
- key-material indicators

Never store secret values. Store:
- location
- type
- fingerprint
- metadata
- evidence hash

#### D-4 Network TLS scanning — P1

When enabled, every active scan requires:
- named authorization
- allowlist
- rate ceiling
- change window
- operator identity
- audit record

Record:
- protocol versions
- cipher suites
- key exchange groups
- certificate chain
- signature algorithms
- hybrid PQC support

Exposure is metadata: `internal | external | dmz`.

#### D-5 Cloud KMS/HSM — P1

Read-only connectors:
- AWS KMS
- Azure Key Vault
- Google Cloud KMS
- PKCS#11 HSM

Never extract key material.

#### D-6 Binary analysis — P1

Use:
- LIEF
- pyelftools

Report `indeterminate` where evidence is insufficient.

---

## 6. Canonical Model

The internal model must be independent of CycloneDX version.

### Entities

- **Tenant**
- **Repository**
- **Scan**
- **Asset**
- **Occurrence**
- **Evidence**
- **Component**
- **Relationship**
- **RiskAssessment**
- **PolicyResult**
- **Advisory**
- **Snapshot**
- **Exemption**
- **AuditEvent**

### Asset

A cryptographic element:
- algorithm
- key
- certificate
- protocol configuration
- library
- cryptographic capability

### Occurrence

Where an asset was discovered:
- repository/file/line
- image/layer
- host/port
- KMS identifier
- artifact

### Evidence

Raw or structured collector output supporting an occurrence.

Secret values are prohibited.

### Component

Software/infrastructure element that `implements` or `uses` an asset.

Fields include:
- criticality: `critical | high | medium | low`
- exposure: `internal | external | dmz | unknown`

### Relationship

Typed relationship:
- `implements`
- `uses`
- `depends_on`
- `contains`
- `observed_on`
- `derived_from`

A component that merely implements a primitive but does not use it on a live data path must not be scored as active exposure.

---

## 7. Normalization and Correlation

Pipeline:

```text
Collector
  -> Evidence envelope
  -> Validation
  -> Parse
  -> Normalize
  -> Identity resolution
  -> Deduplicate
  -> Correlate
  -> Confidence assignment
  -> Risk/policy
  -> Export
```

Stable identity must survive repeated scans.

Multiple collectors finding the same asset produce one logical asset with multiple evidence records.

### Identity gap to solve

The MVP must define deterministic identity keys before implementation. Proposed hierarchy:

1. Explicit immutable identifier where available.
2. Repository + commit + path + semantic location.
3. Package coordinates + version.
4. Certificate fingerprint.
5. Normalized algorithm/configuration fingerprint.

Ambiguous matches must be retained as separate assets rather than silently merged.

---

## 8. Confidence Model

Every finding:

- `confirmed`
- `probable`
- `unconfirmed`

Rules:
- deterministic high-confidence signatures may produce `confirmed`
- correlated evidence may produce `probable`
- LLM output can only produce `unconfirmed`
- confidence cannot be hidden from reports

The MVP must document how evidence raises or lowers confidence.

---

## 9. Risk Engine

### 9.1 Mosca

Model:

`X + Y > Z`

Where:
- X = confidentiality/data lifetime
- Y = migration time
- Z = scenario for time to a cryptographically relevant quantum computer

Z must be a scenario range:
- conservative
- central
- optimistic

ECDAT must never present a single Q-day date as fact.

### 9.2 QARS

QARS is an invented, transparent prioritization heuristic, not a scientific measurement.

Inputs:
- temporal risk
- data sensitivity
- network exposure

Score:
`0.0–1.0`

Tenant-configurable weights.

The UI must expose:
- each input
- weight
- resulting score
- explanation

Changing weights must re-score without rescanning.

### 9.3 Criticality separation

Criticality is organizational metadata, not a hidden QARS multiplier.

A critical asset must remain visible even if its computed QARS is low.

---

## 10. Policy Engine

Use OPA/Rego.

Policy result must contain:
- policy pack/version
- rule ID
- component
- offending property
- verdict
- explanation
- source/reference

Initial policy packs:
- CNSA 2.0
- NIST IR 8547
- FIPS 140-3
- customer baseline

Policy packs must be versioned and dated.

Do not hardcode a universal RSA threshold into the risk engine. Thresholds belong in policy.

---

## 11. Migration Advisory

Advisories are recommendations for architect review, not automatic migrations.

Initial mappings:

| Purpose | Advisory family |
|---|---|
| KEM/key establishment | ML-KEM (FIPS 203) |
| Signatures/certificates | ML-DSA (FIPS 204) |
| Long-lived firmware/code signing | SLH-DSA (FIPS 205) |
| FN-DSA | Represent, but do not recommend as production until finalized |
| HQC | Represent, but do not recommend as production until standardized |

Where transition is appropriate, hybrid guidance can include X25519 + ML-KEM.

### Variant selection

Show 2–3 parameter options where applicable, including:
- NIST security level
- public key size
- signature/ciphertext size
- latency class
- criticality/exposure context

The system must not claim that one parameter set is universally correct.

---

## 12. Evidence

MVP evidence chain:

```text
Finding evidence
    -> canonical CBOM snapshot
    -> canonical serialization
    -> hash
    -> Merkle tree
    -> Merkle root
    -> RFC 3161 timestamp token
    -> offline verification
```

Audit events:
- scan started/completed
- scope changed
- finding created/updated
- score changed
- policy changed
- override
- exemption
- export
- snapshot
- timestamp

The offline verifier must not require the ECDAT server.

Public testnets are not the default evidence anchor.

---

## 13. CI/CD

CLI:

```bash
ecdat scan ./repo
ecdat policy check scan.json
ecdat export --format cyclonedx
ecdat gate --policy customer-baseline
```

CI modes:
- blocking
- warn-only
- baseline
- exemption with expiry

GitHub Actions, GitLab CI and Jenkins can use the CLI.

---

## 14. UI

### Dashboard

Show:
- asset count
- crypto findings
- policy violations
- QARS distribution
- critical assets
- exposure distribution
- trend

### Asset Explorer

Filters:
- algorithm
- repository
- language
- criticality
- exposure
- confidence
- policy verdict
- risk
- scan

Every finding must be traceable to collector, run and location within three clicks.

### Finding page

Display:
- what was found
- where
- why it matters
- evidence
- confidence
- risk inputs
- policy failures
- advisory
- historical scans

---

## 15. API

REST API with OpenAPI.

Minimum endpoints:

```text
POST   /api/v1/scans
GET    /api/v1/scans/{id}
GET    /api/v1/assets
GET    /api/v1/assets/{id}
GET    /api/v1/findings
GET    /api/v1/risk
GET    /api/v1/policies
POST   /api/v1/policies/evaluate
GET    /api/v1/advisories
POST   /api/v1/exports
POST   /api/v1/snapshots
GET    /api/v1/audit
```

UI capabilities must be API-accessible.

---

## 16. Exports

P0:
- CycloneDX 1.7
- JSON
- CSV
- SARIF

P1:
- CycloneDX 1.6
- PDF
- evidence pack

CycloneDX serialization must use adapters so a future version does not require changing the canonical model.

---

## 17. Security Requirements

- Collectors run out-of-process.
- Sandbox untrusted input.
- Resource limits.
- No collector network egress except ingestion API where applicable.
- No secret/key-value persistence.
- Evidence values must be redacted/fingerprinted.
- Encrypt data in transit and at rest.
- Least privilege credentials.
- Tenant isolation.
- Append-only audit trail.
- ECDAT must publish its own CBOM.
- Supply-chain pinning and dependency scanning are required for ECDAT itself.

---

## 18. MVP Deployment

Primary free/self-hosted deployment:

```text
React + TypeScript
        |
     FastAPI
        |
  ECDAT workers
        |
  PostgreSQL + JSONB
        |
      OPA
        |
     Valkey
```

Optional:
- Apache AGE
- Ollama
- OpenBao
- MinIO-compatible object storage
- Prometheus/Grafana/Loki

Docker Compose is the default MVP deployment.

Kubernetes/k3s is a production packaging milestone, not a prerequisite for development.

---

## 19. Free/Open-Source Technology Strategy

| Requirement | Preferred MVP | Paid/cloud alternative |
|---|---|---|
| Database | PostgreSQL | Managed PostgreSQL |
| Graph | Apache AGE | Neo4j Enterprise |
| Queue/cache | Valkey | Managed Redis |
| AI | Ollama/vLLM | AWS Bedrock |
| Secrets | OpenBao | Cloud KMS/Secrets services |
| Object storage | Local filesystem / S3-compatible OSS | AWS S3 |
| Tickets | OpenProject/custom API | Jira/ServiceNow |
| Orchestration | Docker Compose | Kubernetes/cloud Kubernetes |
| Monitoring | Prometheus + Grafana | Cloud monitoring |
| Logs | Loki | Cloud logging |
| TSA | Self-hosted/customer TSA | Hosted TSA |
| Identity | Keycloak | Enterprise IdP |
| CI | GitHub/GitLab/Jenkins | Managed CI |

All paid services should be adapters.

---

## 20. Technical and Logic Gaps to Close

### G-1 Detection semantics

Define exactly what constitutes:
- cryptographic implementation
- cryptographic use
- capability
- inactive code
- dead code
- test code

### G-2 Dependency-to-crypto mapping

A package containing OpenSSL does not prove an application actively uses RSA.

The MVP needs evidence levels for dependency findings.

### G-3 Key-material detection

Define secret detection fingerprints and false-positive handling.

Never retain values.

### G-4 Asset identity

Create deterministic cross-collector identity rules.

### G-5 Risk input ownership

Define who supplies X and Y:
- customer
- default policy
- asset class
- evidence-derived estimate

Every default must be visible.

### G-6 QARS calibration

Initial weights are product defaults, not scientific truth.

Store weighting profile with every score.

### G-7 Exposure semantics

Network exposure and business criticality must remain separate fields.

### G-8 Policy source authority

Every shipped policy rule needs:
- source document
- version/date
- section/reference
- effective date
- jurisdiction/scope

### G-9 Advisory evidence

Recommendations must distinguish:
- finalized standards
- drafts
- candidates
- transitional guidance

### G-10 LLM boundary

LLM-generated findings cannot become `confirmed` without deterministic or human confirmation.

### G-11 Evidence immutability

Define canonical serialization before hashing. The same logical snapshot must generate the same hash.

### G-12 Multi-tenancy

Tenant ID must be mandatory on all persistent records and enforced at the database/API layer.

### G-13 Authorization

Define permissions for:
- administrator
- analyst
- developer
- auditor

### G-14 Scan safety

Active network scanning must be opt-in and governance-controlled.

### G-15 Standards churn

CycloneDX version changes must be isolated to serialization adapters.

### G-16 Collector failure

A failed collector must produce an explicit partial-scan state rather than silently producing an apparently complete inventory.

### G-17 Unknown state

The system needs explicit states such as:
- unknown
- indeterminate
- not observed
- unsupported

These must not be confused with "secure."

### G-18 Benchmark corpus

A labelled corpus is required before claiming language support or accuracy.

### G-19 Reproducibility

Store:
- collector version
- rule version
- policy pack version
- canonical model version
- model/version if AI is used
- input revision
- timestamp

### G-20 Scale

Do not claim the 100k-asset NFR until benchmarked. The MVP should define a smaller verified scale target.

---

## 21. MVP Acceptance Criteria

The MVP is complete when:

1. A user can scan a Java/Python repository.
2. Findings contain location and provenance.
3. Dependencies are represented and linked where evidence permits.
4. Findings are deduplicated.
5. Confidence is visible.
6. QARS and Mosca scenarios are reproducible.
7. Policies return traceable results.
8. Advisories identify appropriate replacement families.
9. CI can block or warn.
10. A valid CycloneDX 1.7 CBOM is generated.
11. Findings can be explored through the UI.
12. Evidence can be exported.
13. Historical scans can be compared.
14. Audit events are recorded.
15. The product runs without paid cloud services.
16. Security tests demonstrate that secrets are not persisted.
17. Benchmark results are published for supported languages.
18. Collector failures and unsupported cases are visible rather than silently omitted.

---

## 22. MVP Release Structure

### M1 — Discovery Spine

- Java/Python source
- dependencies
- canonical model
- evidence envelope
- PostgreSQL
- CycloneDX 1.7
- CLI
- REST API

### M2 — Trust and Breadth

- container/filesystem
- deterministic rules
- deduplication
- correlation
- confidence
- asset explorer
- scan governance

### M3 — Risk and Policy

- Mosca
- QARS
- OPA
- policy packs
- advisory engine
- CI gate
- baselines/exemptions

### M4 — Evidence

- immutable snapshots
- Merkle
- RFC 3161
- offline verifier
- audit export
- auditor workflow

### M5 — Enterprise Extensions

- KMS/HSM
- binaries
- network TLS
- certificates
- local LLM
- SSO/RBAC
- ticketing
- Kubernetes
- scale hardening

---

## 23. Open Questions

1. How are X and Y defaults sourced and overridden?
2. What is the exact minimum evidence required for `confirmed`?
3. How should dynamic/runtime use be represented when only static evidence exists?
4. Which certificate lifecycle integrations should be supported?
5. What exact auditor report templates are required?
6. What migration adapter is required for CycloneDX 2.x?
7. What is the supported-asset definition for the benchmark?
8. How should conflicting collectors be reconciled?
9. How should tenant-specific policy exceptions be versioned and audited?
10. What is the verified MVP scale target?

---

## 24. Success Metrics

- Detection recall and false-positive rate by supported language.
- Percentage of findings with provenance.
- Percentage of findings with deterministic confirmation.
- Duplicate rate after correlation.
- Policy evaluation correctness.
- CBOM schema validation rate.
- CI false-failure rate.
- Scan duration.
- API/dashboard latency.
- Evidence verification success rate.
- Percentage of customer data remaining within tenant boundary.


---

# 25. Architecture Gap Resolutions

The following decisions are normative for the MVP. They replace ambiguous architecture choices with implementable behavior.

## A-1. Event and Job Queue Semantics

PostgreSQL is the system of record for jobs; Valkey is an acceleration/wakeup mechanism and must not be the authoritative job store.

Job states:

```text
QUEUED
  -> CLAIMED
  -> RUNNING
     -> SUCCEEDED
     -> FAILED_RETRYABLE
     -> FAILED_FINAL
     -> CANCELLED
     -> EXPIRED
```

Every job must contain:

```text
id
tenant_id
scan_id
job_type
state
priority
idempotency_key
attempt
max_attempts
scheduled_at
started_at
completed_at
worker_id
error_code
error_message
input_hash
created_at
updated_at
```

Required job types:

```text
SCAN_CREATE
COLLECT_SOURCE
COLLECT_DEPENDENCY
COLLECT_CONTAINER
NORMALIZE
CORRELATE
CALCULATE_RISK
EVALUATE_POLICY
GENERATE_ADVISORY
GENERATE_CBOM
CREATE_SNAPSHOT
TIMESTAMP_SNAPSHOT
GENERATE_EXPORT
```

Jobs must be idempotent. A worker retry must not create duplicate findings or duplicate snapshots.

## A-2. PostgreSQL Partitioning

Do not partition all tables.

Partition only high-volume append-oriented tables:

```text
evidence
audit_events
scan_events
job_events
```

Use monthly range partitions on `created_at`. Tenant filtering remains indexed with `tenant_id`.

Core relational tables such as `assets`, `components`, `repositories`, `relationships`, `policy_rules`, and `advisories` remain ordinary tables until measured scale requires partitioning.

## A-3. Evidence Retention

Separate:
1. logical findings,
2. evidence metadata,
3. raw/large evidence payloads.

Default MVP retention:

| Object | Retention |
|---|---:|
| Findings | Indefinite |
| Risk assessments | Indefinite |
| Policy results | Indefinite |
| Audit events | Indefinite |
| Snapshot metadata | Indefinite |
| Merkle roots | Indefinite |
| RFC 3161 tokens | Indefinite |
| Raw collector evidence | 90 days |
| Large intermediate artifacts | 30 days |
| Secret/key values | Never |

Retention is customer-configurable. A `retention_hold=true` flag prevents normal deletion.

Deleting raw evidence must not invalidate an immutable snapshot.

## A-4. Apache AGE Adoption

PostgreSQL is mandatory. Apache AGE is optional.

Use relational recursive queries first. Enable AGE when measured requirements justify graph persistence, including any of:

- interactive blast-radius workflow is required;
- more than 10,000 graph nodes per tenant;
- more than 100,000 relationship edges;
- relational traversal exceeds the approved latency target;
- migration-wave visualization becomes a P1 workflow.

NetworkX remains an offline analysis library and is not a persistent graph store.

## A-5. Multi-Tenant Isolation

MVP uses shared PostgreSQL with mandatory `tenant_id` and PostgreSQL Row-Level Security (RLS).

Every tenant-owned table must have:

```text
tenant_id UUID NOT NULL
```

Application authorization and database RLS are both required. Application code alone is not a sufficient isolation boundary.

Higher-isolation deployments may later use separate schemas, databases, or separate customer installations without changing the logical data model.

## A-6. Authentication

Keycloak is the default free/self-hosted identity provider.

Supported protocols:
- OIDC
- SAML
- local users for development

MVP roles:

```text
ADMIN
ANALYST
DEVELOPER
AUDITOR
```

Auditors can read, export and verify evidence but cannot alter policies, scores, scope, exemptions or evidence.

## A-7. API Rate Limits

Use token-bucket rate limiting.

Initial engineering defaults:

| Operation | Default |
|---|---:|
| Read API | 600 requests/min/user |
| Write API | 60 requests/min/user |
| Scan creation | 10/hour/user |
| Export generation | 20/hour/user |
| Tenant aggregate | 1,000 requests/min |

Limits are implementation defaults and are configurable. Exceeded limits return HTTP 429 with `Retry-After`.

## A-8. Worker Retry and Dead-Letter Semantics

Retryable failures include temporary infrastructure errors, transient external API failures, TSA timeouts and worker crashes.

Non-retryable failures include invalid input, unsupported input, permission errors, schema errors and invalid policy definitions.

Default backoff:

```text
Attempt 1 -> immediate
Attempt 2 -> 10 seconds
Attempt 3 -> 30 seconds
Attempt 4 -> 2 minutes
Attempt 5 -> 10 minutes
```

After the configured maximum, the job becomes `FAILED_FINAL` and creates a dead-letter event. A scan with a failed required stage cannot be presented as complete.

---

# 26. Logic Gap Resolutions

## L-1. Static Implementation vs Actual Use

ECDAT must distinguish:

```text
CAPABILITY
STATIC_USE
RUNTIME_USE
UNKNOWN
```

A source-level API invocation is `STATIC_USE`. A runtime observation requires runtime evidence.

Static evidence must never be described as proof of production runtime execution.

## L-2. Dependency Capability vs Active Usage

Dependency evidence must distinguish:

```text
DEPENDENCY_CAPABILITY
DEPENDENCY_IMPORT
STATIC_API_USE
RUNTIME_USE
```

The existence of cryptographic functionality inside a package does not establish that the application actively uses that functionality.

## L-3. Identity Collision Rules

Identity resolution order:

1. stable external identifier;
2. certificate fingerprint;
3. package coordinates;
4. repository + commit + path + semantic location;
5. normalized cryptographic observation.

Automatic merge requires a matching identity rule, compatible asset type and compatible context.

Ambiguous matches become `POSSIBLE_DUPLICATE` and are not silently merged.

## L-4. Confidence Promotion

Confidence states:

```text
UNCONFIRMED
  -> PROBABLE
  -> CONFIRMED
```

`CONFIRMED` requires:
- collector identity and version;
- input revision;
- exact location/resource;
- normalized observation;
- deterministic rule or authoritative external observation;
- evidence fingerprint.

LLM-only findings can never become `CONFIRMED`.

## L-5. X/Y Risk Defaults

### X — confidentiality/data lifetime

Source priority:

```text
customer asset classification
    ->
customer retention/data metadata
    ->
policy-pack default
    ->
ECDAT generic default
```

Store:

```text
x_value
x_source
x_source_version
x_override
```

ECDAT must never silently convert a generic assumption into a customer fact.

### Y — migration time

Y is derived from:
- asset class;
- migration complexity band;
- customer override.

Store:

```text
y_value
y_min
y_max
y_source
y_assumption
```

X and Y assumptions are versioned with the risk assessment.

## L-6. QARS Calibration

QARS is explicitly a transparent prioritization heuristic, not an objective measurement.

Initial profile:

```text
temporal weight = 1/3
sensitivity weight = 1/3
exposure weight = 1/3
```

Store the complete weighting profile with every score.

Capture architect overrides:

```text
original_score
override_score
weight_profile
reason
reviewer
timestamp
```

Later analysis may report override rate and systematic disagreement.

## L-7. Criticality Independence

`criticality` and `QARS` are independent fields.

Criticality is not silently multiplied into QARS.

Views must support:
- QARS/risk filtering;
- critical-assets filtering;
- combined filtering.

## L-8. Exposure Derivation

Network exposure is derived from:
- approved scan authorization;
- target allowlist metadata;
- network segment/context;
- operator-provided scope metadata.

Allowed values:

```text
internal
external
dmz
unknown
```

Insufficient evidence produces `unknown`, never an implicit `internal`.

## L-9. Policy Source and Version Lifecycle

Policy packs use immutable versions.

Lifecycle:

```text
DRAFT
 -> REVIEW
 -> ACTIVE
 -> SUPERSEDED
 -> RETIRED
```

Each version records:

```text
policy_pack_id
version
source_document
source_version
published_at
effective_from
effective_until
jurisdiction
checksum
```

Active versions are never edited in place.

## L-10. Advisory Confidence and Standard Status

Each advisory carries:

```text
advisory_confidence:
  HIGH | MEDIUM | LOW

standard_status:
  FINAL
  DRAFT
  SELECTED_NOT_FINAL
  DEPRECATED
  EXPERIMENTAL
```

Only finalized standards are eligible for production recommendations by default. Non-final algorithms may remain representable in the data model without being recommended for production.

## L-11. LLM Confirmation Workflow

LLM flow:

```text
LLM
  -> hypothesis
  -> UNCONFIRMED
  -> deterministic verification OR human confirmation
  -> CONFIRMED
```

Store:
- provider;
- model;
- model version;
- prompt version;
- input hash;
- output hash;
- timestamp;
- reviewer;
- review status.

LLM output cannot directly change compliance status, QARS, or audit evidence.

## L-12. Indeterminate vs Unsupported

These states are distinct.

`UNSUPPORTED`: ECDAT does not claim coverage.

`INDETERMINATE`: ECDAT attempted analysis, but available evidence was insufficient.

`NOT_OBSERVED`: ECDAT supports the target, scanned it successfully, and did not observe the target behavior.

None of these states is equivalent to `SECURE`.

## L-13. Partial Scan Semantics

Overall scan states:

```text
COMPLETE
PARTIAL
FAILED
CANCELLED
```

Collector states:

```text
SUCCESS
PARTIAL
FAILED
UNSUPPORTED
SKIPPED
```

A scan with a failed required collector cannot be shown as a complete inventory.

## L-14. Exemption Precedence

An exemption never deletes or modifies the underlying policy failure.

Represent:

```text
policy_result = FAIL
exemption = ACTIVE
gate_result = PASS_WITH_EXCEPTION
```

Exemptions contain:
- reason;
- owner;
- approver;
- creation date;
- expiry date;
- scope;
- policy rule.

Expired exemptions are ignored according to policy.

## L-15. Historical Reproducibility

Store every version that affects a result:

```text
collector_version
rule_version
policy_pack_version
canonical_model_version
risk_profile_version
advisory_version
LLM_model_version
prompt_version
repository_revision
scan_configuration_version
```

Historical CBOMs are reproduced from stored evidence and versions, not by assuming today's toolchain will produce yesterday's result.

---

# 27. Exact Evidence Required for `CONFIRMED`

Minimum confirmed evidence by type:

### Source
- exact file and location;
- input revision;
- parsed AST evidence;
- deterministic rule;
- normalized algorithm/operation.

### Dependency
- package coordinates;
- exact version;
- resolved dependency path;
- verified package metadata.

This confirms capability, not necessarily active use.

### Network
- successful handshake;
- endpoint;
- timestamp;
- observed protocol/cipher/key-exchange/signature parameters.

### KMS/HSM
- authoritative provider response;
- resource identifier;
- algorithm/key metadata;
- caller identity;
- timestamp.

### Certificate
- certificate fingerprint;
- parsed certificate;
- issuer/subject;
- signature algorithm;
- validity information.

---

# 28. Dynamic Use Representation

All findings must include:

```text
usage_evidence:
  static
  dynamic
  inferred
  unknown
```

Example:

```text
implements = true
static_use = true
runtime_use = unknown
```

Absence of runtime evidence must not be interpreted as proof of non-use.

---

# 29. Certificate Integration Scope

The MVP provides a certificate connector interface and supports generic REST/CSV/JSON imports.

Dedicated integrations for Keyfactor, Venafi and additional certificate lifecycle systems are post-MVP adapters.

ECDAT remains a discovery/correlation product rather than a certificate lifecycle management platform.

---

# 30. Auditor Evidence Pack

Canonical evidence pack contents:

```text
01-executive-summary.pdf
02-scope-and-methodology.pdf
03-asset-inventory.csv
04-policy-results.csv
05-exceptions.csv
06-risk-assessments.csv
07-finding-provenance.json
08-cbom.json
09-snapshot.json
10-merkle-proof.json
11-rfc3161-token.tsr
12-audit-log.json
```

Required report sections:
- scope;
- method;
- coverage;
- findings;
- policy compliance;
- exceptions;
- risk assumptions;
- advisories;
- evidence integrity;
- audit trail;
- limitations.

---

# 31. CycloneDX Version Migration

The internal canonical model is never coupled to the CycloneDX serialization version.

```text
Canonical Model
  ├── CycloneDX 1.6 adapter
  ├── CycloneDX 1.7 adapter
  └── future CycloneDX 2.x adapter
```

A CycloneDX version change must not require a canonical database migration unless the canonical model itself changes.

---

# 32. Benchmark Definition

An asset class is considered supported only when it has:

1. a collector;
2. benchmark fixtures;
3. hand-labelled ground truth;
4. measured precision/recall;
5. documented acceptance results.

MVP benchmark classes:

```text
Java source crypto
Python source crypto
npm dependencies
PyPI dependencies
Maven dependencies
Go modules
container crypto/configuration
```

The corpus must contain:
- positive cases;
- negative cases;
- wrappers;
- aliases;
- edge cases;
- unused implementations;
- dependency-only crypto.

---

# 33. Conflicting Collector Reconciliation

Conflicting evidence is never overwritten.

Example:

```text
Collector A -> RSA-2048
Collector B -> RSA-3072
```

The finding retains both evidence records and receives:

```text
conflict = true
```

Resolution priority:

```text
direct authoritative observation
    >
deterministic static evidence
    >
correlated evidence
    >
LLM inference
```

Lower-priority evidence is retained for auditability.

## 34. Tenant-Specific Policy Exceptions

Tenant policies are immutable versions layered over base packs.

```text
Base policy
    +
tenant policy version
    +
exception
```

Every exception change is audited.

An exception cannot modify historical results.

---

# 35. Verified MVP Scale Target

The verified MVP target is:

```text
10,000 assets
500 repositories
25,000 certificates
10 concurrent scans
```

Initial engineering objectives:

```text
common API p95 < 500 ms
representative UI initial data < 2 seconds
no cross-tenant data leakage
collector crash isolation
```

The larger PRD targets remain GA objectives:

```text
100k assets
5k repositories
250k certificates
24-hour full-estate rescan
```

Those GA figures must not be claimed until benchmarked.

---

# 36. Normative MVP Rules

The MVP implementation must follow these rules:

1. PostgreSQL is the system of record.
2. Valkey accelerates queues but is not the source of truth.
3. RLS is part of tenant isolation.
4. Keycloak is the default free/self-hosted identity provider.
5. AGE is optional until graph workload justifies it.
6. Evidence is immutable; raw evidence has explicit retention.
7. Static use is not runtime use.
8. Dependency capability is not active usage.
9. LLM output is a hypothesis.
10. `CONFIRMED` requires deterministic/authoritative evidence.
11. `UNKNOWN` is not `SECURE`.
12. `PARTIAL` is not `COMPLETE`.
13. Criticality is not QARS.
14. X/Y assumptions are explicit, sourced and versioned.
15. Policies are immutable versions.
16. Exemptions override gates, not historical findings.
17. Advisory standard status is explicit.
18. CycloneDX is a serialization adapter, not the internal model.
19. Conflicting evidence is retained.
20. Historical results are reproducible from versioned inputs.
