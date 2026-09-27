"""Real app authentication, revocation and isolation regressions."""
import time
import uuid
import pytest
from fastapi.testclient import TestClient
from ecdat.apps.api.config import get_settings
from ecdat.apps.api.main import create_app
from ecdat.apps.api.auth import store

PASSWORD = 'a test only long passphrase'

@pytest.fixture
def clients(tmp_path, monkeypatch):
    monkeypatch.setenv('EVIDENCE_STORE_PATH',str(tmp_path))
    monkeypatch.setenv('ENVIRONMENT','development')
    get_settings.cache_clear()
    store.create_user('alice',PASSWORD,legacy_owner=True)
    store.create_user('bob',PASSWORD)
    with TestClient(create_app()) as alice, TestClient(create_app()) as bob:
        yield alice,bob
    get_settings.cache_clear()

def sign_in(client,name='alice'):
    response=client.post('/api/v1/session',json={'username':name,'password':PASSWORD})
    assert response.status_code==200,response.text
    return response

def test_no_guest_token_or_anonymous_bypass(clients):
    client,_=clients
    for path in ['/api/v1/uploads','/api/v1/workspace/assets','/api/v1/advisories','/openapi.json','/api/v1/uploads/config']:
        assert client.get(path).status_code==401
        assert client.get(path,headers={'X-Guest-Session':store.LEGACY_OWNER}).status_code==401
        assert client.get(path,headers={'Authorization':'Bearer '+store.LEGACY_OWNER}).status_code==401
    assert client.post('/api/v1/session/guest').status_code==401
    assert client.post('/api/v1/session/guest/'+store.LEGACY_OWNER+'/cleanup').status_code==401
    assert client.post('/api/v1/session',json={'username':'alice','password':'wrong'}).status_code==401
    assert client.post('/api/v1/session',json={'username':"x' OR 1=1 --",'password':PASSWORD}).status_code==401
    response=sign_in(client)
    assert 'HttpOnly' in response.headers['set-cookie'] and 'SameSite=strict' in response.headers['set-cookie']
    token=client.cookies.get(store.COOKIE)
    assert PASSWORD not in token
    assert client.get('/api/v1/workspace/assets').status_code==200
    assert client.delete('/api/v1/session').status_code==200
    assert client.get('/api/v1/workspace/assets',headers={'Authorization':'Bearer '+token}).status_code==401

def test_two_user_scan_export_isolation(clients):
    alice,bob=clients
    sign_in(alice);sign_in(bob,'bob')
    response=alice.post('/api/v1/uploads',data={'kind':'source'},files={'file':('crypto.js',b'RSA MD5')})
    assert response.status_code==202,response.text
    scan=response.json()['id']
    assert alice.get('/api/v1/uploads/'+scan).json()['status']=='completed'
    assert bob.get('/api/v1/uploads/'+scan).status_code==404
    assert bob.get('/api/v1/uploads/'+scan+'/artifacts/original').status_code==404
    assert bob.get('/api/v1/uploads',headers={'X-Guest-Session':store.LEGACY_OWNER}).json()==[]
    assert bob.get('/api/v1/workspace/assets').json()['total']==0
    assert bob.get('/api/v1/advisories').json()==[]
    assert bob.get('/api/v1/workspace/export/cyclonedx').json()['components']==[]
    assert len(alice.get('/api/v1/workspace/export/cyclonedx').json()['components'])==2
    with store.database() as db:
        assert all(PASSWORD not in row['password'] for row in db.execute('SELECT password FROM users'))
        assert db.execute('SELECT digest FROM sessions').fetchone()['digest'] != alice.cookies.get(store.COOKIE)

def test_expiry_reset_disable_and_csrf(clients):
    alice,_=clients
    sign_in(alice)
    assert alice.delete('/api/v1/session',headers={'Origin':'https://evil.invalid'}).status_code==403
    assert alice.delete('/api/v1/session',headers={'Sec-Fetch-Site':'cross-site'}).status_code==403
    with store.database() as db: db.execute('UPDATE sessions SET expires=?',(time.time()-1,))
    assert alice.get('/api/v1/uploads').status_code==401
    sign_in(alice)
    store.reset_password('alice','a different long passphrase')
    assert alice.get('/api/v1/uploads').status_code==401
    assert alice.post('/api/v1/session',json={'username':'alice','password':PASSWORD}).status_code==401
    assert alice.post('/api/v1/session',json={'username':'alice','password':'a different long passphrase'}).status_code==200
    with store.database() as db: db.execute("UPDATE users SET active=0 WHERE username='alice'")
    assert alice.get('/api/v1/uploads').status_code==401

def test_login_throttle_and_password_validation(clients):
    client,_=clients
    for _ in range(10):
        assert client.post('/api/v1/session',json={'username':'alice','password':'wrong'}).status_code==401
    assert client.post('/api/v1/session',json={'username':'alice','password':PASSWORD}).status_code==429
    with pytest.raises(ValueError): store.create_user('short','tiny')

def test_legacy_scans_only_available_to_explicit_owner(clients):
    import json
    from pathlib import Path
    alice,bob=clients
    ident=str(uuid.uuid4())
    folder=Path(get_settings().evidence_store_path)/'uploads'/ident
    folder.mkdir(parents=True)
    (folder/'record.json').write_text(json.dumps({'id':ident,'filename':'old.js','kind':'source','created_at':'2026-09-26T00:00:00Z','status':'completed','findings':[]}))
    (folder/'original').write_bytes(b'legacy artifact')
    sign_in(alice);sign_in(bob,'bob')
    assert alice.get('/api/v1/uploads/'+ident+'/artifacts/original').content==b'legacy artifact'
    assert ident in [s['id'] for s in alice.get('/api/v1/uploads').json()]
    assert bob.get('/api/v1/uploads/'+ident).status_code==404
    assert bob.get('/api/v1/uploads').json()==[]


def test_every_protected_openapi_operation_rejects_anonymous(clients):
    """Exercise every registered HTTP operation, including malformed IDs/bodies."""
    client, _ = clients
    import re
    checked = 0
    for path, operations in client.app.openapi()['paths'].items():
        if not path.startswith('/api/') or path in {'/api/v1/session', '/api/v1/health', '/api/v1/ready'}:
            continue
        concrete = re.sub(r'\{[^}]+\}', '00000000-0000-0000-0000-000000000001', path)
        for method in operations:
            if method.lower() not in {'get', 'post', 'put', 'patch', 'delete', 'head'}:
                continue
            response = client.request(method, concrete, headers={'X-Guest-Session': store.LEGACY_OWNER, 'Authorization': 'Bearer forged'})
            assert response.status_code == 401, (method, path, response.status_code)
            checked += 1
    assert checked >= 10
