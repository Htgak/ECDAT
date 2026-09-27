"""Exercise the real application boundary, not just the isolated upload router."""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from ecdat.apps.api.config import get_settings
from ecdat.apps.api.main import create_app
from ecdat.apps.api.auth.dependencies import get_current_user, WorkspaceUser
from ecdat.apps.api.routers import uploads
from ecdat.core.discovery.assessment import enrich

_TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


def _mock_user():
    return WorkspaceUser(id=_TEST_USER_ID, username="tester")


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv('EVIDENCE_STORE_PATH', str(tmp_path))
    monkeypatch.setenv('ENVIRONMENT', 'development')
    get_settings.cache_clear()
    app = create_app()
    from ecdat.apps.api.auth import store
    store.create_user("tester", "test passphrase for prototype", legacy_owner=True)
    with TestClient(app) as client:
        assert client.post("/api/v1/session", json={"username":"tester", "password":"test passphrase for prototype"}).status_code == 200
        yield client
    get_settings.cache_clear()


def upload(client, content=b'const algorithms = ["RSA", "MD5", "ML-DSA"];', context=None):
    response = client.post('/api/v1/uploads', data={'kind': 'source', 'context': json.dumps(context or {})},
                           files={'file': ('pipeline-audit.js', content)})
    assert response.status_code == 202, response.text
    scan = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert scan['status'] == 'completed', scan
    return scan


def test_one_scan_reaches_inventory_policies_advice_exports(app_client):
    scan = upload(app_client)
    assets = app_client.get('/api/v1/workspace/assets').json()['items']
    assert len(assets) == scan['finding_count'] == 3  # ML-DSA must not also create DSA.
    assert all(asset['qars_score'] is None for asset in assets)
    assert app_client.get('/api/v1/workspace/scans').json()[0]['id'] == scan['id']
    for asset in assets:
        detail = app_client.get('/api/v1/workspace/assets/' + asset['id'])
        assert detail.status_code == 200
        assert detail.json()['scan_id'] == scan['id']
    policies = app_client.get('/api/v1/workspace/policies').json()
    rsa_size = next(row for row in policies if row['rule_id'] == 'CRYPTO-RSA-001')
    assert rsa_size['verdict'] == 'unknown'
    assert any(row['rule_id'] == 'CRYPTO-LEGACY-001' and row['verdict'] == 'warn' for row in policies)
    assert len(app_client.get('/api/v1/advisories').json()) == 3
    assert app_client.get('/api/v1/workspace/evidence').json()[0]['checksums_available']
    for fmt in ('cyclonedx', 'sarif', 'csv'):
        response = app_client.get('/api/v1/workspace/export/' + fmt)
        assert response.status_code == 200, response.text
        assert 'RSA' in response.text
        if fmt == 'cyclonedx':
            assert len(response.json()['components']) == 3
        elif fmt == 'sarif':
            assert len(response.json()['runs'][0]['results']) == 3


def test_partial_context_remains_partial_after_repeated_read(app_client):
    scan = upload(app_client, context={'criticality': 'critical'})
    for _ in range(3):
        for finding in app_client.get('/api/v1/workspace/assets').json()['items']:
            assert finding['qars_score'] is None
            assert finding['finding']['context'] == {'criticality': 'critical'}
            assert finding['finding']['mosca']['verdict'] == 'not_assessed'


def test_risk_fields_survive_reassessment():
    finding = {'algorithm': 'RSA', 'location': 'a', 'evidence': 'String indicator'}
    for _ in range(3):
        enrich([finding], {'criticality': 'high'})
        assert finding['risk_score'] is None
        assert finding['context'] == {'criticality': 'high'}


def test_origin_host_and_retired_pipelines(app_client):
    assert app_client.post('/api/v1/uploads', headers={'Origin': 'https://attacker.invalid'}).status_code == 403
    assert app_client.get('/api/v1/workspace/assets', headers={'Host': 'attacker.invalid'}).status_code == 400
    for path in ['/api/v1/scans', '/api/v1/scans/', '/api/v1/exports']:
        assert app_client.post(path, json={'repository_id': 'file:///etc'}).status_code in {404, 410}
    for url in ['file:///etc', 'http://127.0.0.1/repo', 'https://github.com@127.0.0.1/repo']:
        assert app_client.post('/api/v1/uploads/repository', json={'url': url}).status_code == 400


def test_upload_server_limits_and_validation(app_client):
    response = app_client.post('/api/v1/uploads', headers={'Content-Length': str(502 * 1024 * 1024)}, content=b'')
    assert response.status_code == 413
    assert app_client.post('/api/v1/uploads', files={'file': ('x.js', b'RSA')}, data={'kind': 'source', 'context': '{"migration_years":-1}'}).status_code == 422
    assert app_client.get('/api/v1/workspace/assets?page=0').status_code == 422
    assert app_client.get('/api/v1/uploads/not-a-uuid/artifacts/original').status_code == 422
    assert app_client.get('/api/v1/uploads/' + str(uuid.uuid4()) + '/artifacts/original').status_code == 404


def test_corrupt_record_does_not_look_like_empty_workspace(app_client):
    root = uploads.storage_root(str(_TEST_USER_ID)) / str(uuid.uuid4())
    root.mkdir(parents=True, exist_ok=True)
    (root / 'record.json').write_text('{invalid')
    assert app_client.get('/api/v1/workspace/assets').status_code == 503
    assert app_client.get('/api/v1/advisories').status_code == 503
    assert app_client.get('/api/v1/uploads/' + root.name).status_code == 503


def test_chunked_request_cannot_bypass_body_limit(app_client):
    def chunks():
        yield b'{"token":"'
        yield b'a' * (1024 * 1024 + 100)
        yield b'"}'
    response = app_client.post('/api/v1/session', content=chunks(), headers={'Content-Type': 'application/json'})
    assert response.status_code == 413


def test_algorithm_configurations_keep_distinct_ids():
    findings = [{'algorithm': 'AES', 'location': 'crypto.py', 'evidence': 'Source observation', 'mode': mode} for mode in ['GCM', 'CBC']]
    enrich(findings, {})
    assert findings[0]['id'] != findings[1]['id']


def test_signing_rsa_reports_authenticity_risk():
    finding = {'algorithm': 'RSA', 'operation': 'sign', 'location': 'crypto.py', 'evidence': 'Source observation'}
    enrich([finding], {'sensitivity': 'restricted'})
    assert 'signature forgery' in finding['sensitive_data_risk']
    assert 'harvest-now' not in finding['sensitive_data_risk']
