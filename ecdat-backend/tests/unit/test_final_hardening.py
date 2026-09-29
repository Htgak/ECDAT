import json

import pytest

from ecdat.core.discovery.assessment import enrich, RiskContext
from ecdat.core.normalization.algorithms import normalize_algorithm
from tests.unit.test_uploads import client, post


@pytest.mark.parametrize('raw,canonical,mode', [
    ('RSA/ECB/PKCS1Padding', 'RSA', 'ECB'), ('AES/GCM/NoPadding', 'AES', 'GCM'),
    ('AES/ECB/PKCS5Padding', 'AES', 'ECB'), ('DESede/CBC/PKCS5Padding', '3DES', 'CBC'),
    ('SHA1', 'SHA-1', None), ('SHA256', 'SHA-256', None),
    ('ML-DSA', 'ML-DSA', None), ('SLH-DSA', 'SLH-DSA', None),
    ('EC', 'EC', None), ('secp256r1', 'EC', None), ('Kyber', 'Kyber', None),
])
def test_normalization(raw, canonical, mode):
    result = normalize_algorithm(raw)
    assert (result.canonical, result.mode) == (canonical, mode)
    assert result.raw == raw


@pytest.mark.parametrize('factory,raw,canonical,operation', [
    ('Cipher', 'RSA/ECB/PKCS1Padding', 'RSA', 'encrypt'),
    ('Cipher', 'AES/GCM/NoPadding', 'AES', 'encrypt'),
    ('Cipher', 'AES/ECB/PKCS5Padding', 'AES', 'encrypt'),
    ('Cipher', 'DESede/CBC/PKCS5Padding', '3DES', 'encrypt'),
    ('MessageDigest', 'SHA1', 'SHA-1', 'digest'),
    ('MessageDigest', 'SHA256', 'SHA-256', 'digest'),
    ('Signature', 'SHA256withRSA', 'RSA', 'sign'),
])
def test_active_pipeline(client, factory, raw, canonical, operation):
    source = f'import javax.crypto.*; import java.security.*; class Demo {{ void run() throws Exception {{ {factory}.getInstance("{raw}"); }} }}'
    response = post(client, 'Demo.java', source.encode())
    record = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert record['status'] == 'completed', record
    f = record['findings'][0]
    assert (f['algorithm_raw'], f['algorithm'], f['operation']) == (raw, canonical, operation)
    assert f['scanner'] == 'java-source'
    if canonical == 'RSA':
        assert f['quantum_transition_status'] == 'quantum_vulnerable_public_key'
        assert f['alternatives'][0] == ('ML-DSA' if operation == 'sign' else 'ML-KEM')
    if '/ECB/' in raw and canonical == 'AES':
        assert any(p['rule_id'] == 'CRYPTO-MODE-001' for p in record['policies'])
    for artifact in ['cbom', 'cbom17', 'sarif']:
        assert client.get('/api/v1/uploads/' + record['id'] + '/artifacts/' + artifact).status_code == 200


def test_alias_and_transparent_score():
    old = RiskContext(data_lifetime_years=8).model_dump(exclude_unset=True)
    assert old == {'protection_lifetime_years': 8}
    context = dict(**old, migration_years=2, quantum_horizon_years=10,
                   criticality='critical', exposure='external', sensitivity='restricted')
    findings = [dict(algorithm='RSA', evidence='Source observation', location='x', operation='sign')]
    enrich(findings, context)
    f = findings[0]
    assert f['mosca']['margin_years'] == 0
    assert f['mosca']['verdict'] == 'act_now'
    assert round(sum(f['planning_priority']['breakdown'].values())) == f['risk_score']


def test_secret_values_do_not_leave_scanner(client, caplog):
    source = b'import hashlib\npassword="do-not-export-password-9372"\ntoken="do-not-export-token-4811"\nkey="-----BEGIN PRIVATE KEY-----"\nvalue=hashlib.sha256(password.encode())\n'
    response = post(client, 'secrets.py', source)
    base = '/api/v1/uploads/' + response.json()['id']
    report = client.get(base).json()
    assert report['status'] == 'completed'
    for artifact in ['report', 'findings', 'cbom', 'cbom17', 'sarif']:
        output = client.get(base + '/artifacts/' + artifact).text
        for secret in ['do-not-export-password-9372', 'do-not-export-token-4811', 'BEGIN PRIVATE KEY']:
            assert secret not in output
            assert secret not in caplog.text


def test_partial_syntax_error_is_not_a_clean_bill(client):
    response = post(client, 'broken.py', b'def broken(:\n')
    record = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert record['status'] == 'completed'
    assert record['coverage']['status'] == 'PARTIAL'
    assert any('not be fully analyzed' in note for note in record['limitations'])


def test_legacy_mosca_never_invents_duration():
    from ecdat.core.risk.mosca import MoscaEngine
    with pytest.raises(ValueError, match='NOT ASSESSED'):
        MoscaEngine().calculate('RSA', x_years=10)


def test_bounded_tool_output(tmp_path):
    import sys
    from ecdat.collectors.binary.process import run_tool
    with pytest.raises(ValueError, match='bounded output'):
        run_tool([sys.executable, '-c', 'import sys; sys.stdout.write("x" * 3000000)'], cwd=str(tmp_path), timeout=10)


def test_tool_timeout(tmp_path):
    import subprocess
    import sys
    from ecdat.collectors.binary.process import run_tool
    with pytest.raises(subprocess.TimeoutExpired):
        run_tool([sys.executable, '-c', 'import time; time.sleep(5)'], cwd=str(tmp_path), timeout=1)


def test_tool_does_not_inherit_application_credentials(tmp_path, monkeypatch):
    import sys
    from ecdat.collectors.binary.process import run_tool
    monkeypatch.setenv('AUTH_PASSWORD', 'not-for-subprocesses')
    result = run_tool([sys.executable, '-c', 'import os; print("AUTH_PASSWORD" in os.environ)'], cwd=str(tmp_path), timeout=10)
    assert result.stdout.strip() == b'False'


def test_binary_symbols_do_not_confuse_related_names():
    from ecdat.collectors.binary.decompiler import _match_symbol_name
    assert 'DSA' not in _match_symbol_name('OQS_SIG_ml_dsa_65_sign')
    assert 'DSA' not in _match_symbol_name('OQS_SIG_slh_dsa_sign')
    assert not _match_symbol_name('caesar_salad')
    assert 'AES' in _match_symbol_name('EVP_aes_256_gcm')
    assert 'Kyber' in _match_symbol_name('OQS_KEM_kyber_768_encaps')
