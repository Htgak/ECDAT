import hashlib
import io
import uuid
import zipfile
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ecdat.apps.api.auth.dependencies import get_current_user
from ecdat.apps.api.routers import uploads
from ecdat.core.discovery.inputs import validate_repository

_TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


def _mock_user():
    user = MagicMock()
    user.id = _TEST_USER_ID
    user.role.value = "user"
    return user


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(uploads, 'get_settings', lambda: SimpleNamespace(evidence_store_path=str(tmp_path)))
    app = FastAPI()
    app.include_router(uploads.router, prefix='/api/v1')
    app.dependency_overrides[get_current_user] = _mock_user
    with TestClient(app) as session:
        yield session


@pytest.mark.parametrize('url', ['file:///tmp/repo', 'https://localhost/a/b', 'https://github.com@evil.test/a/b', 'https://token@github.com/a/b', 'http://github.com/a/b', 'https://github.com/a/b?token=secret'])
def test_reject_unsafe_repository(client, url):
    assert client.post('/api/v1/uploads/repository', json={'url': url}).status_code == 400


def test_repository_scan_artifacts(client, monkeypatch):
    def snapshot(folder, url, ref):
        assert ref == 'release/test'
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('src/hash.py', 'import hashlib\nx = hashlib.md5(b"test")')
        content = data.getvalue()
        (folder / 'original').write_bytes(content)
        return dict(size=len(content), sha256=hashlib.sha256(content).hexdigest(), commit='a' * 40)
    monkeypatch.setattr(uploads, 'repository_snapshot', snapshot)
    response = client.post('/api/v1/uploads/repository', json={'url': 'https://github.com/example/repo.git', 'ref': 'release/test'})
    assert response.status_code == 202
    scan_id = response.json()['id']
    result = client.get('/api/v1/uploads/' + scan_id).json()
    assert result['status'] == 'completed', result
    assert result['kind'] == 'git' and result['commit'] == 'a' * 40
    assert result['findings'][0]['location'] == 'src/hash.py'
    for artifact in ['original', 'report', 'findings']:
        assert client.get(f'/api/v1/uploads/{scan_id}/artifacts/{artifact}').status_code == 200


def test_failed_clone_never_scans_other_source(client, monkeypatch):
    def fail(*args):
        raise ValueError('Repository could not be fetched.')
    monkeypatch.setattr(uploads, 'repository_snapshot', fail)
    monkeypatch.setattr(uploads, 'perform_scan', lambda *args: pytest.fail('Must not scan after failed acquisition'))
    response = client.post('/api/v1/uploads/repository', json={'url': 'https://github.com/example/missing'})
    scan_id = response.json()['id']
    result = client.get('/api/v1/uploads/' + scan_id).json()
    assert result['status'] == 'failed'
    assert result['finding_count'] == 0
    assert client.get(f'/api/v1/uploads/{scan_id}/artifacts/original').status_code == 409


def test_ref_validation():
    with pytest.raises(ValueError):
        validate_repository('https://github.com/a/b', '--upload-pack=anything')
    assert validate_repository('https://gitlab.com/group/subgroup/repo', 'main')
