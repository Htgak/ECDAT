"""Local prototype accounts and revocable sessions; no external database service."""
from contextlib import contextmanager, closing
import getpass
import hashlib
import hmac
import secrets
import sqlite3
import time
import uuid
import re
from threading import BoundedSemaphore
from pathlib import Path
import json

from ecdat.apps.api.config import get_settings

LEGACY_OWNER = '00000000-0000-0000-0000-000000000001'
COOKIE = 'ecdat_session'
KDF_SLOTS = BoundedSemaphore(2)

def derive(password, salt):
    # Bound memory even when several login requests arrive together.
    with KDF_SLOTS:
        return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=131072, r=8, p=1, maxmem=256*1024*1024).hex()


@contextmanager
def database():
    root = Path(get_settings().evidence_store_path)
    root.mkdir(parents=True, exist_ok=True)
    path = root / 'auth.sqlite3'
    with closing(sqlite3.connect(path, timeout=10)) as db, db:
        db.row_factory = sqlite3.Row
        db.executescript('''
          CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
          CREATE TABLE IF NOT EXISTS sessions (digest TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            expires REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY, count INTEGER NOT NULL, until REAL NOT NULL);
        ''')
        columns = {row['name'] for row in db.execute('PRAGMA table_info(users)')}
        if 'role' not in columns:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if 'source' not in columns:
            db.execute("ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local'")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        yield db


def username(value):
    value = value.strip().lower()
    if not re.fullmatch(r'[a-z0-9][a-z0-9_.@+-]{2,79}', value):
        raise ValueError('Username must be 3-80 letters, digits or . _ @ + - characters.')
    return value


def hash_password(password, min_len=15):
    if not min_len <= len(password) <= 128:
        raise ValueError(f'Use a password or passphrase of {min_len}-128 characters.')
    salt = secrets.token_hex(16)
    digest = derive(password, salt)
    return f'scrypt${salt}${digest}'


def check_password(password, encoded):
    _, salt, expected = encoded.split('$')
    actual = derive(password, salt)
    return hmac.compare_digest(actual, expected)


def sync_env_users():
    """Synchronize explicit environment identities once at startup, preserving stored IDs."""
    settings = get_settings()
    configured = {}
    if settings.auth_password:
        if not settings.auth_username:
            raise ValueError('AUTH_USERNAME is required when AUTH_PASSWORD is set.')
        configured[username(settings.auth_username)] = (settings.auth_password, 'admin')
    if settings.auth_users:
        raw = settings.auth_users.strip()
        try:
            if raw.startswith(('{', '[')):
                data = json.loads(raw)
                pairs = data.items() if isinstance(data, dict) else [(x['username'], x['password']) for x in data]
            else:
                pairs = [item.strip().split(':', 1) for item in raw.split(',')]
            for name, password in pairs:
                name = username(name)
                if name in configured or not isinstance(password, str):
                    raise ValueError()
                configured[name] = (password, 'user')
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ValueError('AUTH_USERS must contain unique normal usernames and string passwords; it cannot redefine the admin.') from None
    for password, _ in configured.values():
        if not 15 <= len(password) <= 128:
            raise ValueError('Environment account passwords must contain 15-128 characters. Set strong credentials in root .env and restart the backend.')
    with database() as db:
        db.execute('BEGIN IMMEDIATE')
        # Removed environment identities lose access; their evidence remains intact.
        for row in db.execute("SELECT id,username FROM users WHERE source='env'").fetchall():
            if row['username'] not in configured:
                db.execute("UPDATE users SET active=0,role='user' WHERE id=?", (row['id'],))
                db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
        for name, (password, role) in configured.items():
            row = db.execute('SELECT * FROM users WHERE username=?', (name,)).fetchone()
            if row:
                changed = not check_password(password,row['password']) or row['role'] != role
                if changed:
                    db.execute('UPDATE users SET password=?,role=?,source=? WHERE id=?', (hash_password(password),role,'env',row['id']))
                    db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
                else:
                    db.execute("UPDATE users SET source='env' WHERE id=?", (row['id'],))
                if role == 'admin':
                    db.execute('UPDATE users SET active=1 WHERE id=?', (row['id'],))
            else:
                owner_free = not db.execute('SELECT 1 FROM users WHERE id=?',(LEGACY_OWNER,)).fetchone()
                ident = LEGACY_OWNER if role == 'admin' and owner_free else str(uuid.uuid4())
                db.execute('INSERT INTO users(id,username,password,role,source) VALUES(?,?,?,?,?)', (ident,name,hash_password(password),role,'env'))


def list_users():
    with database() as db:
        return [dict(row) for row in db.execute('SELECT id,username,role,active,source FROM users ORDER BY username')]


def manage_user(ident, *, password=None, active=None):
    encoded = hash_password(password) if password is not None else None
    with database() as db:
        row = db.execute('SELECT * FROM users WHERE id=?', (str(ident),)).fetchone()
        if not row:
            raise LookupError('Account not found.')
        if row['role'] == 'admin':
            raise ValueError('Manage the administrator through .env and restart the backend.')
        if encoded and row['source'] == 'env':
            raise ValueError('This password is managed by AUTH_USERS. Update .env and restart.')
        if encoded:
            db.execute('UPDATE users SET password=? WHERE id=?',(encoded,str(ident)))
        if active is not None:
            db.execute('UPDATE users SET active=? WHERE id=?',(int(active),str(ident)))
        db.execute('DELETE FROM sessions WHERE user_id=?',(str(ident),))


def create_user(name, password, legacy_owner=False):
    name, encoded = username(name), hash_password(password)
    ident = LEGACY_OWNER if legacy_owner else str(uuid.uuid4())
    with database() as db:
        db.execute('INSERT INTO users(id,username,password) VALUES(?,?,?)', (ident,name,encoded))
    return ident


def reset_password(name, password):
    encoded = hash_password(password)
    with database() as db:
        user = db.execute('SELECT id,source FROM users WHERE username=?', (username(name),)).fetchone()
        if not user:
            raise ValueError('Account not found.')
        if user['source'] == 'env':
            raise ValueError('Change environment-managed passwords in .env and restart the backend.')
        db.execute('UPDATE users SET password=? WHERE id=?', (encoded,user['id']))
        db.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))


def throttle(key):
    now = time.time()
    key = hashlib.sha256(key.encode()).hexdigest()
    with database() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM attempts WHERE until<=?', (now,))
        row = db.execute('SELECT count FROM attempts WHERE key=?', (key,)).fetchone()
        if row and row['count'] >= 10:
            return False
        db.execute('INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1', (key,now+60))
    return True


def login(name, password):
    with database() as db:
        user_row = db.execute('SELECT * FROM users WHERE username=?', (name.strip().lower(),)).fetchone()
    encoded = user_row['password'] if user_row else 'scrypt$' + '00'*16 + '$' + '00'*64
    valid = check_password(password, encoded)
    if not valid or not user_row or not user_row['active']:
        return None
    token = secrets.token_urlsafe(32)
    with database() as db:
        db.execute('DELETE FROM sessions WHERE expires<=?', (time.time(),))
        db.execute('INSERT INTO sessions VALUES(?,?,?)', (hashlib.sha256(token.encode()).hexdigest(),user_row['id'],time.time()+3600))
    return token


def resolve(token):
    if not token or len(token)>256:
        return None
    with database() as db:
        row = db.execute('SELECT users.id,users.username,users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE digest=? AND expires>? AND active=1',
            (hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone()
    return dict(row) if row else None


def revoke(token):
    with database() as db:
        db.execute('DELETE FROM sessions WHERE digest=?', (hashlib.sha256((token or '').encode()).hexdigest(),))


def token_from(request):
    auth = request.headers.get('authorization','')
    return auth[7:] if auth.startswith('Bearer ') else request.cookies.get(COOKIE)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Provision prototype accounts locally; passwords are prompted, never command-line arguments.')
    parser.add_argument('action', choices=['create','reset-password','disable','list'])
    parser.add_argument('username', nargs='?')
    parser.add_argument('--legacy-owner', action='store_true', help='Assign existing default-workspace scans to this account (create only).')
    args = parser.parse_args()
    try:
        if args.action == 'list':
            with database() as db:
                for row in db.execute('SELECT id,username,role,active,source FROM users'):
                    print(dict(row))
            return
        if not args.username:
            parser.error('username is required')
        if args.legacy_owner and args.action != 'create':
            parser.error('--legacy-owner is only supported for create')
        if args.action == 'disable':
            with database() as db:
                account = db.execute('SELECT role,source FROM users WHERE username=?', (username(args.username),)).fetchone()
                if account and (account['role'] == 'admin' or account['source'] == 'env'):
                    raise ValueError('Manage environment accounts in root .env and restart the backend.')
                changed = db.execute('UPDATE users SET active=0 WHERE username=?', (username(args.username),))
                if not changed.rowcount:
                    raise ValueError('Account not found.')
                db.execute('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username=?)', (username(args.username),))
        else:
            password = getpass.getpass('Password (15-128 characters): ')
            if password != getpass.getpass('Confirm password: '):
                raise ValueError('Passwords do not match.')
            if args.action == 'create':
                create_user(args.username,password,args.legacy_owner)
            else:
                reset_password(args.username,password)
        print('Account updated.')
    except (ValueError,sqlite3.IntegrityError) as exc:
        parser.exit(1, str(exc)+'\n')

if __name__ == '__main__':
    main()
