"""Explicit, reproducible planning assumptions; never infer business context."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field


class RiskContext(BaseModel):
    model_config = ConfigDict(extra='forbid')
    data_lifetime_years: float = Field(5, ge=0, le=100, allow_inf_nan=False)
    migration_years: float = Field(2, ge=0, le=30, allow_inf_nan=False)
    quantum_horizon_years: float = Field(10, gt=0, le=100, allow_inf_nan=False)
    criticality: Literal['low', 'medium', 'high', 'critical'] = 'medium'
    exposure: Literal['internal', 'external'] = 'internal'
    sensitivity: Literal['public', 'internal', 'confidential', 'restricted'] = 'confidential'
    priority: Literal['balanced', 'latency', 'cost', 'assurance'] = 'balanced'


class DeclaredAsset(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=200)
    type: Literal['algorithm', 'key', 'certificate', 'protocol', 'library', 'hardware', 'cloud_service']
    algorithm: str = Field('Unknown', min_length=1, max_length=100)
    version: str | None = Field(None, max_length=100)
    mode: str | None = Field(None, max_length=40)
    key_size: int | None = Field(None, gt=0, le=65536)
    location: str = Field('Declared inventory', max_length=500)
    context: RiskContext | None = None


class InfrastructureInventory(BaseModel):
    model_config = ConfigDict(extra='forbid')
    assets: list[DeclaredAsset] = Field(min_length=1, max_length=5000)


QUANTUM = {'RSA', 'DSA', 'DH', 'ECDH', 'ECDSA', 'EC', 'ED25519', 'ED448', 'X25519', 'X448'}
LEGACY = {'MD5', 'SHA-1', 'SHA1', 'DES', '3DES', 'DESEDE', 'RC4', 'ARC4'}
REFERENCES = ['https://csrc.nist.gov/pubs/fips/203/final', 'https://csrc.nist.gov/pubs/fips/204/final',
              'https://csrc.nist.gov/pubs/fips/205/final']


def enrich(findings: list[dict], context: dict) -> dict:
    default = RiskContext.model_validate(context)
    for finding in findings:
        supplied = dict(finding.get('context') or context)
        ctx = RiskContext.model_validate(supplied)
        algorithm = finding['algorithm'].upper().replace('_', '-')
        finding.setdefault('asset_type', 'algorithm')
        finding.setdefault('confidence', 'observed' if finding['evidence'] != 'String indicator' else 'indicator')
        finding['id'] = hashlib.sha256(json.dumps([finding['algorithm'], finding['location'], finding.get('line'),
                                                 finding['asset_type'], finding.get('version'), finding.get('name'), finding.get('fingerprint'), finding.get('evidence'),
                                                 finding.get('mode'), finding.get('key_size'), finding.get('operation')]).encode()).hexdigest()[:24]
        finding['context'] = ctx.model_dump()
        # Library capability, protocol presence and unknown key material are not a confirmed primitive use.
        vulnerable = algorithm in QUANTUM and finding['asset_type'] not in {'library', 'protocol'}
        legacy = algorithm in LEGACY
        gap = ctx.data_lifetime_years + ctx.migration_years - ctx.quantum_horizon_years
        verdict = 'act_now' if gap > 0 else 'monitor' if gap >= -2 else 'within_horizon'
        finding['quantum_status'] = 'vulnerable' if vulnerable else 'not_assessed'
        finding['sensitive_data_risk'] = (
            'Potential harvest-now-decrypt-later exposure: confirm this primitive protects confidential data in transit or at rest.'
            if vulnerable and ctx.sensitivity in {'confidential', 'restricted'} and algorithm not in {'DSA', 'ECDSA', 'ED25519', 'ED448'} and 'sign' not in (finding.get('operation') or '').lower()
            else 'Future signature forgery may affect authenticity and long-lived trust.' if vulnerable
            else 'Sensitive-data impact requires usage and configuration review.')
        if algorithm in {'AES', 'CHACHA20', 'SHA-256', 'SHA-384', 'SHA-512', 'ML-KEM', 'ML-DSA', 'SLH-DSA'}:
            finding['quantum_status'] = 'configuration_review'
        finding['mosca'] = {'applicable': vulnerable, 'verdict': verdict if vulnerable else 'not_applicable',
                            'x_years': ctx.data_lifetime_years, 'y_years': ctx.migration_years,
                            'z_years': ctx.quantum_horizon_years, 'margin_years': round(-gap, 2),
                            'basis': 'User-selected planning assumptions, not a forecast of quantum arrival'}
        sensitivity = {'public': .1, 'internal': .4, 'confidential': .75, 'restricted': 1}[ctx.sensitivity]
        criticality = {'low': .25, 'medium': .5, 'high': .75, 'critical': 1}[ctx.criticality]
        temporal = 1 if legacy or vulnerable and verdict == 'act_now' else .6 if vulnerable else .2
        finding['risk_score'] = round(100 * (.4 * temporal + .25 * criticality + .2 * sensitivity + .15 * (1 if ctx.exposure == 'external' else .4)))
        finding['priority'] = 'review' if vulnerable or legacy or finding['asset_type'] == 'key' else finding.get('priority', 'info')
        operation = (finding.get('operation') or '').lower()
        if vulnerable:
            signing = algorithm in {'ECDSA', 'DSA', 'ED25519', 'ED448'} or 'sign' in operation
            exchange = algorithm in {'DH', 'ECDH', 'X25519', 'X448'} or any(x in operation for x in ['encrypt', 'exchange', 'establish'])
            finding['recommendation'] = ('Evaluate ML-DSA for signatures; consider SLH-DSA where hash-based signatures fit.' if signing else
                'Evaluate ML-KEM for key establishment, with a protocol-supported classical/PQC hybrid during transition.' if exchange else
                'Confirm whether this primitive signs or establishes keys. Evaluate ML-DSA for signatures or ML-KEM for key establishment.')
            finding['alternatives'] = ['ML-DSA', 'SLH-DSA'] if signing else ['ML-KEM', 'Protocol-supported hybrid'] if exchange else ['ML-KEM (key establishment)', 'ML-DSA (signatures)']
            finding['migration_effort'] = 'high' if finding['asset_type'] in {'hardware', 'cloud_service', 'certificate'} else 'medium'
            if ctx.priority == 'latency':
                finding['recommendation'] += ' Benchmark ML-DSA against SLH-DSA for signature workloads; for key establishment compare supported ML-KEM parameter sets and hybrid handshake sizes.'
            elif ctx.priority == 'cost':
                finding['recommendation'] += ' Prefer a supported provider/library upgrade before custom protocol changes; budget for certificate and hardware dependencies.'
            elif ctx.priority == 'assurance':
                finding['recommendation'] += ' Evaluate higher security parameter sets against interoperability and resource limits; use reviewed implementations.'
        elif legacy:
            finding['recommendation'] = 'Replace security-sensitive hashing with SHA-256 or stronger; use a password KDF for passwords.' if 'SHA' in algorithm or algorithm == 'MD5' else 'Replace legacy encryption with an authenticated cipher such as AES-256-GCM; review nonce and key management.'
            finding['alternatives'] = ['SHA-256 / SHA-384'] if 'SHA' in algorithm or algorithm == 'MD5' else ['AES-256-GCM', 'ChaCha20-Poly1305']
            finding['migration_effort'] = 'medium'
        elif algorithm in {'AES', 'AES-128', 'AES-192', 'AES-256'}:
            finding['recommendation'] = 'Review AES key size and mode. For new or migrated encryption evaluate AES-256-GCM with unique nonces; existing AES-256 authenticated encryption does not need replacement solely because of quantum risk.'
            finding['alternatives'] = ['AES-256-GCM (authenticated encryption)']
            finding['migration_effort'] = 'requires assessment'
        else:
            finding.setdefault('recommendation', 'Confirm actual usage, supported algorithms and configuration before selecting a migration.')
            finding['alternatives'] = []
            finding['migration_effort'] = 'requires assessment'
        finding['tradeoffs'] = {
            'latency': 'Measure handshake size and p95 latency on the target platform; PQC keys and signatures can increase network traffic.',
            'cost': 'Prioritize supported library upgrades; include certificate, hardware and service replacement costs in the migration estimate.',
            'assurance': 'Evaluate validated implementations and interoperability; larger parameter sets add bandwidth and storage costs.',
            'balanced': 'Benchmark latency, bandwidth, memory and operating costs before selecting parameters; estimates are not measurements.'
        }[ctx.priority]
        finding['references'] = REFERENCES if vulnerable else []
        # Missing organizational facts must not become an invented assessment.
        planning_known = all(key in supplied for key in ['data_lifetime_years', 'migration_years', 'quantum_horizon_years'])
        risk_known = planning_known and all(key in supplied for key in ['criticality', 'sensitivity', 'exposure'])
        finding['context'] = {key: value for key, value in ctx.model_dump().items() if key in supplied}
        finding['context_source'] = 'user' if supplied else 'not_provided'
        if not planning_known:
            finding['mosca'].update(verdict='not_assessed', applicable=False, x_years=None, y_years=None, z_years=None, margin_years=None,
                                    basis='Provide data lifetime, migration duration and a quantum arrival scenario to calculate Mosca.')
        if not risk_known:
            finding['risk_score'] = None
        if 'sensitivity' not in supplied:
            finding['sensitive_data_risk'] = 'Data sensitivity has not been supplied. Confirm the protected data and operation to assess confidentiality or authenticity impact.'
    return {'asset_types': dict(Counter(f['asset_type'] for f in findings)),
            'quantum_vulnerable': sum(f['quantum_status'] == 'vulnerable' for f in findings),
            'act_now': sum(f['mosca']['verdict'] == 'act_now' for f in findings),
            'legacy': sum(f['algorithm'].upper() in LEGACY for f in findings),
            'context': {key: value for key, value in default.model_dump().items() if key in context}}


def standard_documents(record: dict) -> tuple[dict, dict]:
    """CycloneDX 1.6 components with crypto inventory and planning properties; SARIF 2.1.0."""
    components = []
    results = []
    for f in record['findings']:
        props = [{'name': 'ecdat:' + key, 'value': json.dumps(f[key]) if isinstance(f[key], (dict, list)) else str(f[key])}
                 for key in ['asset_type', 'algorithm', 'location', 'evidence', 'confidence', 'context', 'mosca', 'risk_score', 'recommendation', 'tradeoffs']]
        for key in ['mode', 'key_size', 'curve', 'provider', 'operation', 'fingerprint', 'expires_at', 'scan_id', 'source_filename']:
            if f.get(key) is not None: props.append({'name': 'ecdat:' + key, 'value': str(f[key])})
        component = {'type': 'library' if f['asset_type'] == 'library' else 'device' if f['asset_type'] == 'hardware' else 'cryptographic-asset',
                     'bom-ref': f['id'], 'name': f.get('name') or f['algorithm'], 'properties': props}
        if component['type'] == 'cryptographic-asset':
            asset_type = f['asset_type'] if f['asset_type'] in {'algorithm', 'certificate', 'protocol'} else 'related-crypto-material'
            component['cryptoProperties'] = {'assetType': asset_type}
        if f.get('version'): component['version'] = f['version']
        components.append(component)
        location = {'artifactLocation': {'uri': quote(f['location'].replace('\\', '/'), safe='/')}}
        if f.get('line'): location['region'] = {'startLine': max(1, f['line'])}
        results.append({'ruleId': 'ECDAT-CRYPTO', 'level': 'warning' if f['priority'] == 'review' else 'note',
                        'message': {'text': f"{f['algorithm']}: {f['recommendation']} Evidence: {f['evidence']}."},
                        'locations': [{'physicalLocation': location}], 'properties': {'riskScore': f['risk_score'], 'mosca': f['mosca']}})
    cbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'serialNumber': 'urn:uuid:' + record['id'], 'metadata': {'timestamp': record['completed_at'],
            'component': {'type': 'application', 'name': record['filename']},
            'properties': [{'name': 'ecdat:context', 'value': json.dumps(record.get('context', {}))}]}, 'components': components}
    if record.get('sha256'):
        cbom['metadata']['properties'].append({'name': 'ecdat:input-sha256', 'value': record['sha256']})
    sarif = {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
             'runs': [{'tool': {'driver': {'name': 'ECDAT', 'version': '0.2.0', 'rules': [{'id': 'ECDAT-CRYPTO', 'shortDescription': {'text': 'Cryptographic artifact discovery'}}]}}, 'results': results}]}
    return cbom, sarif


def write_standard_reports(folder: Path, record: dict) -> None:
    cbom, sarif = standard_documents(record)
    (folder / 'cbom.json').write_text(json.dumps(cbom, indent=2), encoding='utf-8')
    (folder / 'results.sarif').write_text(json.dumps(sarif, indent=2), encoding='utf-8')
    hashes = {name: hashlib.sha256((folder / name).read_bytes()).hexdigest() for name in ['report.json', 'findings.csv', 'cbom.json', 'results.sarif']}
    hashes['original'] = record['sha256']
    (folder / 'checksums.json').write_text(json.dumps({'algorithm': 'sha256', 'artifacts': hashes}, indent=2), encoding='utf-8')
