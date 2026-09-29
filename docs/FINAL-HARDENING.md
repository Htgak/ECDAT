# ECDAT SIH26164 hardening verification

This is an implementation and verification record, not a security certification.
The React / FastAPI / filesystem evidence store / SQLite architecture is unchanged.

## Active product behavior

- Source observations preserve their raw algorithm, operation, scanner and rule identity.
  Normalization runs before deduplication, risk and policy. EC stays ambiguous;
  Kyber, Dilithium, SPHINCS and Falcon are not relabelled as final NIST standards.
- X is **required protection lifetime**, Y is organizational migration duration,
  and Z is an organization-selected planning scenario, not a prediction of Q-Day.
  Missing values have no numerical defaults. Margin is `Z - (X + Y)`; a margin
  at or below zero is urgent, `(0, 2]` is monitor, and above two is within the
  selected horizon. Certificate expiry does not set X.
- Findings separately expose classical, quantum-transition and organization-policy
  statuses. Local baseline review results are not CNSA/FIPS compliance decisions.
  SHA-1/MD5 require usage review; HMAC-SHA1 is not normalized to SHA-1.
- Recommendations are operation-aware candidates, with rationale and references.
  AES-128/192/256 are not automatically failed for quantum transition. Historical
  advisory APIs no longer invent migration months or certify CNSA compliance.
- The website shows application identity, posture counts, score contributions,
  evidence details, certificate metadata, scan coverage and provenance. Unknown
  fields remain unknown. A zero finding count does not establish absence of crypto.
- The capabilities endpoint is `GET /api/v1/uploads/capabilities`.
- Downloads include JSON, CSV, CycloneDX 1.6 and 1.7, SARIF and SHA-256 integrity
  verification checksums. These checksums are not externally signed or tamper-proof.

## Measured Crypto Zoo

Run from `ecdat-backend`:

```sh
uv sync --frozen --extra dev
uv run python benchmarks/run_full_benchmark.py
```

The runner invokes the actual upload `perform_scan`, including normalization,
deduplication, assessment, policies, report generation and offline schema validation.
Ground truth lives in `tests/benchmark/crypto_zoo/manifest.json`.

| Measurement | Result |
|---|---:|
| Labelled cases | 56 |
| Negative controls | 12 |
| Ground-truth algorithm artefacts | 46 |
| True positives | 42 |
| False positives | 0 |
| Misses | 4 |
| Precision | 100.0% |
| Recall | 91.3% |
| F1 | 95.5% |

Matching uses **case + canonical algorithm**, collapsing repeated observations
within a case. Negative cases contribute false positives. This is not a benchmark
of complete semantic understanding, operation correctness, or runtime use. The
binary fixtures are static indicator bytes, not executable programs.

Known misses are committed rather than removed: Python `hashlib.new` with a
variable algorithm, Python liboqs KEM and signature factories, and Java
`Cipher.getInstance` with a variable algorithm. More dataflow/provider support is
future work. Machine-readable results: `ecdat-backend/benchmarks/results/crypto-zoo.json`.

## Public-repository validation

The active repository acquisition and scan path scanned
[pallets/itsdangerous](https://github.com/pallets/itsdangerous/tree/672971d66a2ef9f85151e53283113f33d642dabd)
at revision `672971d66a2ef9f85151e53283113f33d642dabd`.

19 files were inspected; 31 were skipped. Coverage is **PARTIAL**.
The scanner reported SHA-1 at `src/itsdangerous/signer.py:45` and a SHA-256 string
indicator in `uv.lock`. Manual source review confirmed the `hashlib.sha1` call;
the lockfile occurrence describes dependency integrity hashes, not proof of
application cryptographic use. Review also found configurable HMAC construction
at lines 63 and 207. ECDAT does not resolve that dataflow, so the SHA-1 observation
must not be read as a finding that HMAC-SHA1 is collision-broken. No exhaustive
repository accuracy claim is made. Results and input hash are recorded in
`ecdat-backend/benchmarks/results/public-repository.json`.

## Offline golden demonstration

`ecdat-backend/QuantumReady-DemoCorp.zip` contains 11 planted findings: RSA
signing, ECDH, SHA-1, 3DES, AES-GCM, ML-KEM/ML-DSA, RSA/EC certificates, a binary
indicator and a dependency declaration. Ground truth is next to its source tree.
Key size is unknown unless the scanner observes it; the fixture does not confer
a claim that nonce/key handling is secure. A separate rootfs TAR demonstrates
container dependency inspection.

1. Build and preload backend/frontend images and dependencies while online.
2. Start the local two-service stack. Use a regular analyst account for scans.
3. Upload `QuantumReady-DemoCorp.zip` as source.
4. Optionally supply X=10, Y=3, Z=10, criticality=critical, sensitivity=restricted,
   exposure=external. These are **demo-entered assumptions**, never hidden defaults.
5. Open RSA signing evidence and its signature migration candidates. Show the
   signed Mosca margin and score contributions. Inspect the binary limitation.
6. Download CBOM 1.7, SARIF and checksums. No external API or schema download occurs.

The non-root, network-disabled scan/export smoke check is:

```sh
docker build -t ecdat-backend:hardening-review ./ecdat-backend
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 2g --cpus 2 \
  --mount type=bind,source=/absolute/path/to/ecdat-backend,target=/fixtures,readonly \
  ecdat-backend:hardening-review /app/.venv/bin/python \
  /fixtures/benchmarks/verify_offline_demo.py /fixtures
```

This passed with 11 source-estate findings, one container dependency finding,
validated exports and UID 10001. This verifies the scan/export path without
networking; it is not a claim that a separate clean physical machine was tested.

## Binary and build boundaries

- Static binary cryptographic indicator and symbol analysis only. Runtime use
  is not confirmed. Optional Ghidra symbols are probable; string/decompiled-text
  findings remain indicators. Packed/encrypted/stripped binaries may be opaque.
- Tools have timeouts, bounded stdout/stderr, a monitored 128 MiB output-directory
  budget, 768 MiB JVM heap and two JVM processors. Compose also limits memory,
  CPUs and process count, drops capabilities and disallows new privileges.
- Tool processes do not inherit application authentication variables. Temporary
  decompiler output is removed, directories are private on POSIX, and uploaded
  application code, containers and native libraries are never executed/loaded.
- The default image omits optional Ghidra/JADX downloads. Opt-in builds require
  explicitly supplied verified SHA-256 values, with exact tool versions. The uv
  image is digest-pinned and Python dependencies are locked.
- Actual Ghidra/JADX executions were not validated here because those tools are
  not installed in the default image. Their adapters, absence, timeouts, output
  limits and secret omission are regression-tested. Static tool subprocesses
  are not a claim of a complete hostile-parser sandbox.

## Standards and schemas

- [NIST PQC FAQ: symmetric cryptography](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/faqs)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [RFC 10024](https://www.rfc-editor.org/info/rfc10024/): TLS 1.3 groups
  X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024. Outside a known protocol,
  recommendations say protocol-supported standardized hybrid.
- [Official CycloneDX 1.7 schema](https://github.com/CycloneDX/specification/tree/1.7/schema)
  and [1.6 schema](https://github.com/CycloneDX/specification/tree/1.6/schema).

Local JSON schemas and their hashes are under
`ecdat-backend/ecdat/integrations/schemas`. Reference resolution is local-only.
Unknown optional crypto properties are omitted. Known modes, padding, functions,
families and parameter sets use schema vocabulary. Naming an algorithm does not
certify an implementation. Unknown OIDs and security levels are not invented.

## Verification scope

All 204 backend regression tests passed (one upstream deprecation warning). Frontend lint and production build passed. Both backend and frontend Docker images built successfully. The static offline demo and responsive production-build rendering passed.
The UI check uses actual golden scan JSON with mocked API transport and captures
390/768/1440px screenshots in `artifacts/hardening-review`; API behavior is covered
separately by backend tests. No live deployment was performed.

Do not label the entire SIH submission finalized solely from this change:
fresh physical-machine setup, real installed decompiler runs, and a jury rehearsal
on the target demo hardware remain operational checks. Existing named Docker
volumes created by root may need operator ownership migration to UID 10001; this
change does not rewrite or delete existing evidence.
