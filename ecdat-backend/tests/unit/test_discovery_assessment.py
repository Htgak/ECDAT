import hashlib
import io
import json
import tarfile
import uuid
import zipfile

import pytest

from ecdat.core.discovery.assessment import enrich
from ecdat.core.discovery.inputs import container_snapshot
from tests.unit.test_uploads import client, post, archive


def tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as stream:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            stream.addfile(member, io.BytesIO(data))
    return out.getvalue()


@pytest.mark.parametrize('x,verdict', [(9, 'act_now'), (8, 'act_now'), (7, 'monitor'), (1, 'within_horizon')])
def test_mosca_boundaries(x, verdict):
    findings = [dict(algorithm='RSA', location='a', evidence='String indicator')]
    enrich(findings, dict(data_lifetime_years=x, migration_years=2, quantum_horizon_years=10, sensitivity="confidential"))
    assert findings[0]['mosca']['verdict'] == verdict
    assert findings[0]['confidence'] == 'indicator'
    assert 'harvest-now' in findings[0]['sensitive_data_risk']


def test_library_not_confirmed_primitive():
    items = [dict(algorithm='RSA', asset_type='library', location='a', evidence='Dependency')]
    enrich(items, {})
    assert not items[0]['mosca']['applicable']


def test_missing_context_never_invents_risk():
    items = [dict(algorithm='RSA', location='a', evidence='String indicator')]
    enrich(items, {})
    assert items[0]['mosca']['verdict'] == 'not_assessed'
    assert items[0]['mosca']['x_years'] is None
    assert items[0]['risk_score'] is None
    assert items[0]['context'] == {}
    assert 'ML-KEM (key establishment)' in items[0]['alternatives']


@pytest.mark.asyncio
async def test_advisories_require_real_findings(tmp_path, monkeypatch):
    from ecdat.apps.api.routers import advisories, workspace
    from types import SimpleNamespace
    user = SimpleNamespace(id=uuid.uuid4())
    monkeypatch.setattr(workspace, 'record_paths', lambda tenant: tmp_path.glob('*/record.json'))
    assert await advisories.get_advisories(user) == []
    folder = tmp_path / 'scan'
    folder.mkdir()
    (folder / 'record.json').write_text(json.dumps({'id': str(uuid.uuid4()), 'created_at': '2026-09-26T00:00:00Z', 'filename': 'real.py', 'status': 'completed', 'findings': [{'algorithm': 'RSA', 'location': 'real.py', 'evidence': 'Source observation', 'operation': 'sign'}]}))
    result = await advisories.get_advisories(user)
    assert len(result) == 1
    assert result[0]['alternatives'] == ['ML-DSA', 'SLH-DSA']
    assert result[0]['estimated_effort_weeks'] is None
    assert result[0]['target_deadline'] is None


def test_assessed_upload_exports(client):
    response = client.post('/api/v1/uploads', data={'kind': 'source', 'context': json.dumps({'data_lifetime_years': 20, 'migration_years': 2, 'quantum_horizon_years': 10, 'criticality': 'critical', 'priority': 'latency'})}, files={'file': ('crypto.js', b'const algorithm = "RSA";')})
    base = '/api/v1/uploads/' + response.json()['id']
    result = client.get(base).json()
    assert result['status'] == 'completed', result
    assert result['assessment']['act_now'] == 1
    assert result['findings'][0]['context']['criticality'] == 'critical'
    for name in ['cbom', 'sarif', 'checksums']:
        assert client.get(base + '/artifacts/' + name).status_code == 200
    checks = client.get(base + '/artifacts/checksums').json()['artifacts']
    assert checks['cbom.json'] == hashlib.sha256(client.get(base + '/artifacts/cbom').content).hexdigest()


def test_invalid_context(client):
    response = client.post('/api/v1/uploads', data={'kind': 'source', 'context': '{"migration_years": -1}'}, files={'file': ('x.js', b'RSA')})
    assert response.status_code == 422


def test_dependencies_and_library(client):
    response = post(client, 'source.zip', archive([('package.json', '{"dependencies":{"crypto-js":"4.2.0"}}')]))
    result = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert result['findings'][0]['version'] == '4.2.0'
    assert result['findings'][0]['asset_type'] == 'library'
    response = post(client, 'crypto.so', b'OpenSSL 3.0.2 RSA', 'library')
    result = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert result['status'] == 'completed'
    assert any(f.get('version') == '3.0.2' for f in result['findings'])


def test_container_upload(client):
    response = post(client, 'rootfs.tar', tar([('app/crypto.js', b'RSA')]), 'container')
    result = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert result['status'] == 'completed', result
    assert result['assessment']['quantum_vulnerable'] == 1


def test_whiteout_preserves_same_layer_files(tmp_path):
    lower = tar([('app/old', b'RSA')])
    upper = tar([('app/new', b'AES'), ('app/.wh..wh..opq', b'')])
    source = tmp_path / 'image.tar'
    source.write_bytes(tar([('manifest.json', b'[{"Layers":["lower.tar","upper.tar"]}]'), ('lower.tar', lower), ('upper.tar', upper)]))
    path, _ = container_snapshot(source, tmp_path)
    with zipfile.ZipFile(path) as archive:
        assert archive.namelist() == ['app/new']


def test_container_traversal_rejected(tmp_path):
    source = tmp_path / 'bad.tar'
    source.write_bytes(tar([('../escape', b'RSA')]))
    with pytest.raises(ValueError):
        container_snapshot(source, tmp_path)

