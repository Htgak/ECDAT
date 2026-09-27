"""File upload contract, archive boundaries, scanners, and durable artifacts."""
import hashlib
import io
import json
import stat
import uuid
import zipfile
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ecdat.apps.api.auth.dependencies import get_current_user
from ecdat.apps.api.routers import uploads

# Fixed test user — tenant_id = user.id for per-user storage scoping
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
    # Override auth dependency so tests don't need a real DB / JWT
    app.dependency_overrides[get_current_user] = _mock_user
    with TestClient(app) as client:
        yield client


def archive(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as zipped:
        for name, data in entries:
            zipped.writestr(name, data)
    return stream.getvalue()


def post(client, filename, content, kind='source'):
    return client.post('/api/v1/uploads', data={'kind': kind}, files={'file': (filename, content, 'application/octet-stream')})


def test_source_scan_and_artifact_roundtrip(client):
    source = b'import hashlib\nresult = hashlib.md5(b"example").hexdigest()\n'
    response = post(client, 'sample.py', source)
    assert response.status_code == 202, response.text
    scan_id = response.json()['id']
    result = client.get(f'/api/v1/uploads/{scan_id}').json()
    assert result['status'] == 'completed', result
    assert any(f['algorithm'] == 'MD5' and f['evidence'] == 'Source observation' for f in result['findings'])
    assert result['sha256'] == hashlib.sha256(source).hexdigest()
    assert result['review_count'] > 0
    assert result['finding_count'] == 1
    assert result['findings'][0]['location'] == 'sample.py'
    for artifact in ['original', 'report', 'findings']:
        download = client.get(f'/api/v1/uploads/{scan_id}/artifacts/{artifact}')
        assert download.status_code == 200
        assert 'attachment' in download.headers['content-disposition']
        if artifact == 'original':
            assert download.content == source
        elif artifact == 'report':
            assert download.json()['sha256'] == result['sha256']
        else:
            assert 'MD5' in download.text
    assert client.get('/api/v1/uploads').json()[0]['id'] == scan_id
    uploads.recover_interrupted()
    assert client.get(f'/api/v1/uploads/{scan_id}').json()['status'] == 'completed'


def test_zip_java_source(client):
    source = 'import javax.crypto.Cipher; class Sample { void run() throws Exception { Cipher.getInstance("DES"); } }'
    response = post(client, 'project.zip', archive([('src/Sample.java', source), ('README.md', 'not source')]))
    result = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert result['status'] == 'completed', result
    assert any(f['algorithm'] == 'DES' for f in result['findings'])
    assert result['skipped_files'] == 1


def test_uppercase_source_extension(client):
    response = post(client, 'project.zip', archive([('src/Sample.PY', 'import hashlib\nx = hashlib.md5(b"test")')]))
    result = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert result['status'] == 'completed'
    assert result['finding_count'] > 0


def test_apk_indicators_are_not_confirmed_usage(client):
    content = archive([('AndroidManifest.xml', '<manifest/>'), ('classes.dex', b'dex\n035\x00 AES RSA MD5')])
    response = post(client, 'sample.apk', content, 'apk')
    assert response.status_code == 202
    result = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert result['status'] == 'completed'
    assert {f['algorithm'] for f in result['findings']} == {'AES', 'RSA', 'MD5'}
    assert all(f['evidence'] == 'String indicator' for f in result['findings'])
    assert any('do not confirm use' in lim for lim in result['limitations'])


def test_exe_header_and_utf16_indicators(client):
    header = bytearray(128)
    header[:2] = b'MZ'
    header[60:64] = (64).to_bytes(4, 'little')
    header[64:68] = b'PE\x00\x00'
    response = post(client, 'sample.exe', bytes(header) + ' RSA SHA-1 '.encode('utf-16-le'), 'exe')
    assert response.status_code == 202
    result = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert result['status'] == 'completed'
    assert {f['algorithm'] for f in result['findings']} == {'RSA', 'SHA-1'}


@pytest.mark.parametrize('name,content,kind', [
    ('fake.exe', b'not a PE executable', 'exe'),
    ('fake.apk', b'not a ZIP', 'apk'),
    ('wrong.py', b'import hashlib', 'apk'),
    ('empty.py', b'', 'source'),
    ('binary.py', b'\x00\xff', 'source'),
    ('missing.apk', archive([('classes.dex', b'RSA')]), 'apk'),
    ('escape.zip', archive([('../escape.py', 'import hashlib')]), 'source'),
    ('absolute.zip', archive([('/escape.py', 'import hashlib')]), 'source'),
    ('drive.zip', archive([('C:/escape.py', 'import hashlib')]), 'source'),
])
def test_reject_invalid_uploads_without_saving(client, name, content, kind):
    assert post(client, name, content, kind).status_code == 400
    assert client.get('/api/v1/uploads').json() == []
    assert list(uploads.storage_root(_TEST_USER_ID).iterdir()) == []


def test_symlinks_and_archive_size_limits(client, monkeypatch):
    link = zipfile.ZipInfo('link.py')
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    assert post(client, 'links.zip', archive([(link, '/etc/passwd')])).status_code == 400
    monkeypatch.setattr(uploads, 'MAX_EXPANDED', 10)
    assert post(client, 'large.zip', archive([('large.py', b'x' * 100)])).status_code == 400


def test_upload_limit(client, monkeypatch):
    monkeypatch.setattr(uploads, 'MAX_UPLOAD', 10)
    assert post(client, 'large.py', b'x' * 100).status_code == 413
    assert not list(uploads.storage_root(_TEST_USER_ID).iterdir())


def test_no_supported_files_is_failed_not_clean(client):
    response = post(client, 'empty.zip', archive([('README.md', 'Hello')]))
    result = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert result['status'] == 'failed'
    assert 'No supported source files' in result['error']
    assert client.get(f"/api/v1/uploads/{result['id']}/artifacts/report").status_code == 409
    assert client.get(f"/api/v1/uploads/{result['id']}/artifacts/original").status_code == 200


def test_restart_marks_interrupted_scan_failed(client):
    response = post(client, 'sample.js', b'const algorithm = "AES";')
    folder, record = uploads.read_record(uploads.uuid.UUID(response.json()['id']), _TEST_USER_ID)
    record['status'] = 'scanning'
    uploads.save_record(folder, record)
    uploads.recover_interrupted()
    recovered = json.loads((folder / 'record.json').read_text())
    assert recovered['status'] == 'failed'
    assert 'interrupted' in recovered['error']


def test_csv_formula_escaping_and_artifact_allowlist(client):
    response = post(client, 'project.zip', archive([('=formula.js', 'const algo = "MD5";')]))
    scan_id = response.json()['id']
    csv = client.get(f'/api/v1/uploads/{scan_id}/artifacts/findings')
    assert "'=formula.js" in csv.text
    assert client.get(f'/api/v1/uploads/{scan_id}/artifacts/record.json').status_code == 422
    assert client.get('/api/v1/uploads/not-an-id').status_code == 422


def test_upload_capacity_is_discoverable(client):
    config = client.get('/api/v1/uploads/config').json()
    assert config['max_upload_bytes'] == 500 * 1024 * 1024
    assert config['max_expanded_bytes'] == 2 * 1024 * 1024 * 1024


@pytest.mark.parametrize('payload,expected', [
    (b'MD5', {'MD5'}),
    (b' ' * 511 + b'MD5 ', {'MD5'}),
    (b' ' * 510 + b'MD5x ', set()),
    (b' ' * 510 + b'XMD5 ', set()),
    (b' ' * 510 + 'RSA SHA-1'.encode('utf-16-le'), {'RSA', 'SHA-1'}),
])
def test_indicator_stream_boundaries(monkeypatch, payload, expected):
    monkeypatch.setattr(uploads, 'CHUNK_SIZE', 512)
    class BoundedReader(io.BytesIO):
        def read(self, size=-1):
            assert 0 < size <= 512
            return super().read(size)
    assert {f['algorithm'] for f in uploads.indicator_stream(BoundedReader(payload), 'binary.exe')} == expected


def test_large_source_uses_explicit_streaming_fallback(client, monkeypatch):
    monkeypatch.setattr(uploads, 'MAX_AST_FILE', 16)
    response = post(client, 'large.py', b'# A large source file\nalgorithm = "MD5"\n')
    result = client.get('/api/v1/uploads/' + response.json()['id']).json()
    assert result['status'] == 'completed'
    assert result['findings'][0]['evidence'] == 'String indicator'
    assert any('instead of parsing source' in note for note in result['limitations'])
