"""Versioned local review rules; these are not compliance certifications."""
from datetime import datetime, timezone

POLICY_VERSION = '2.0.0'


def evaluate(findings: list[dict], scan_id: str) -> list[dict]:
    results = []
    evaluated_at = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        algorithm = finding['algorithm'].upper().replace('_', '-')
        checks = []
        if algorithm in {'MD5', 'SHA1', 'SHA-1', 'DES', '3DES', 'DESEDE', 'RC4', 'ARC4'}:
            checks.append(('CRYPTO-LEGACY-001', 'Review legacy cryptography', 'HIGH', 'algorithm', algorithm, 'warn' if algorithm in {'MD5', 'SHA1', 'SHA-1'} else 'fail', 'Review security-sensitive use of this legacy primitive.'))
        if algorithm == 'AES' and finding.get('mode') == 'ECB':
            checks.append(('CRYPTO-MODE-001', 'Review ECB mode', 'HIGH', 'mode', 'ECB', 'fail', 'ECB exposes repeated plaintext patterns; review authenticated encryption.'))
        if algorithm == 'RSA':
            size = finding.get('key_size')
            verdict = 'unknown' if size is None else 'fail' if size < 2048 else 'pass'
            checks.append(('CRYPTO-RSA-001', 'RSA minimum key length', 'HIGH', 'key_size', size, verdict,
                           'RSA key length must be at least 2048 bits. Passing this rule does not establish quantum resistance.'))
        if finding.get('quantum_status') == 'vulnerable':
            checks.append(('PQC-MIGRATION-001', 'Review quantum-vulnerable public keys', 'MEDIUM', 'algorithm', algorithm, 'warn',
                           'Confirm operation and plan a supported PQC or hybrid migration.'))
        if finding.get('asset_type') == 'key':
            checks.append(('CRYPTO-KEY-001', 'Review private key in scanned artifact', 'HIGH', 'asset_type', 'key', 'warn',
                           'A private-key marker or parsed key was found. Confirm whether the artifact should contain it; report omits key material.'))
        for rule_id, name, severity, prop, value, verdict, explanation in checks:
            if verdict == 'fail' and finding.get('confidence') == 'indicator':
                verdict = 'warn'
                explanation += ' String evidence alone does not confirm runtime use.'
            results.append({'id': f"{scan_id}:{finding['id']}:{rule_id}", 'scan_id': scan_id,
                            'asset_id': finding['id'], 'asset_algorithm': finding['algorithm'],
                            'location': finding['location'], 'rule_id': rule_id, 'rule_name': name,
                            'standard': 'ECDAT review baseline', 'policy_version': POLICY_VERSION,
                            'severity': severity, 'verdict': verdict, 'offending_property': prop,
                            'offending_value': None if value is None else str(value),
                            'explanation': explanation, 'created_at': evaluated_at,
                            'evidence': finding['evidence'], 'engine': 'local-deterministic'})
    return results
