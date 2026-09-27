import uuid
import pytest
from fastapi.testclient import TestClient
from ecdat.apps.api.main import create_app
from ecdat.apps.api.config import get_settings
from ecdat.apps.api.auth import store

PASSWORD='admin test passphrase only'
USER_PASSWORD='normal user passphrase only'

@pytest.fixture
def admin_app(tmp_path,monkeypatch):
    monkeypatch.setenv('EVIDENCE_STORE_PATH',str(tmp_path))
    monkeypatch.setenv('AUTH_USERNAME','operator')
    monkeypatch.setenv('AUTH_PASSWORD',PASSWORD)
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        assert client.post('/api/v1/session',json={'username':'operator','password':PASSWORD}).status_code==200
        yield client

def test_admin_can_create_multiple_users_without_sharing_scans(admin_app):
    alice=admin_app.post('/api/v1/admin/users',json={'username':'alice','password':USER_PASSWORD})
    bob=admin_app.post('/api/v1/admin/users',json={'username':'bob','password':USER_PASSWORD})
    assert alice.status_code==bob.status_code==201
    assert alice.json()['id']!=bob.json()['id']
    assert alice.json()['role']=='user'
    assert admin_app.post('/api/v1/admin/users',json={'username':'evil','password':USER_PASSWORD,'role':'admin'}).status_code==422
    assert admin_app.post('/api/v1/admin/users',json={'username':'alice','password':USER_PASSWORD}).status_code==409
    assert len(admin_app.get('/api/v1/admin/users').json())==3
    with TestClient(create_app()) as a,TestClient(create_app()) as b:
        for c,name in [(a,'alice'),(b,'bob')]:
            assert c.post('/api/v1/session',json={'username':name,'password':USER_PASSWORD}).status_code==200
            assert c.get('/api/v1/admin/users').status_code==403
            assert c.post('/api/v1/admin/users',json={'username':'other','password':USER_PASSWORD}).status_code==403
        response=a.post('/api/v1/uploads',data={'kind':'source'},files={'file':('a.js',b'RSA')})
        assert response.status_code==202
        scan=response.json()['id']
        assert b.get('/api/v1/uploads/'+scan).status_code==404
        assert admin_app.get('/api/v1/uploads/'+scan).status_code==404
        assert b.get('/api/v1/workspace/export/cyclonedx').json()['components']==[]
        assert a.get('/api/v1/workspace/assets').json()['total']==1
        assert admin_app.patch('/api/v1/admin/users/'+alice.json()['id'],json={'active':False}).status_code==200
        assert a.get('/api/v1/uploads').status_code==401
        assert a.post('/api/v1/session',json={'username':'alice','password':USER_PASSWORD}).status_code==401
        assert admin_app.patch('/api/v1/admin/users/'+alice.json()['id'],json={'active':True,'password':'replacement passphrase for alice'}).status_code==200
        assert a.post('/api/v1/session',json={'username':'alice','password':USER_PASSWORD}).status_code==401
        assert a.post('/api/v1/session',json={'username':'alice','password':'replacement passphrase for alice'}).status_code==200
        assert a.get('/api/v1/uploads/'+scan).status_code==200

def test_env_rotation_preserves_id_and_revokes_old_password(admin_app,monkeypatch):
    user=admin_app.get('/api/v1/session').json()['user']
    assert user['role']=='admin'
    assert admin_app.patch('/api/v1/admin/users/'+user['id'],json={'active':False}).status_code==422
    monkeypatch.setenv('AUTH_PASSWORD','rotated admin passphrase only')
    get_settings.cache_clear();store.sync_env_users()
    assert admin_app.get('/api/v1/uploads').status_code==401
    assert admin_app.post('/api/v1/session',json={'username':'operator','password':PASSWORD}).status_code==401
    response=admin_app.post('/api/v1/session',json={'username':'operator','password':'rotated admin passphrase only'})
    assert response.json()['user']['id']==user['id']

def test_env_adoption_preserves_preexisting_uuid(tmp_path,monkeypatch):
    monkeypatch.setenv('EVIDENCE_STORE_PATH',str(tmp_path));get_settings.cache_clear()
    ident=store.create_user('operator',USER_PASSWORD)
    monkeypatch.setenv('AUTH_USERNAME','operator');monkeypatch.setenv('AUTH_PASSWORD',PASSWORD)
    get_settings.cache_clear();store.sync_env_users()
    token=store.login('operator',PASSWORD)
    assert store.resolve(token)['id']==ident
    assert store.resolve(token)['role']=='admin'
    assert store.login('operator',USER_PASSWORD) is None

def test_admin_configuration_command_is_not_available(monkeypatch):
    import pytest
    monkeypatch.setattr('sys.argv', ['store', 'configure-admin', 'operator'])
    with pytest.raises(SystemExit) as exc:
        store.main()
    assert exc.value.code == 2
