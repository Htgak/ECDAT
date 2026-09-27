"""Authenticated prototype sessions and HTTP boundary controls."""
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, ConfigDict
import sqlite3
import uuid
from ecdat.apps.api.auth.dependencies import AdminUser
from starlette.responses import JSONResponse
from ecdat.apps.api.config import get_settings
from ecdat.apps.api.auth import store

router = APIRouter()

class Login(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=1, max_length=128)

@router.get('/session')
def session(request: Request):
    user = store.resolve(store.token_from(request))
    return {'required': True, 'authenticated': bool(user), 'user': user}

@router.post('/session')
def login(body: Login, request: Request, response: Response):
    peer = request.client.host if request.client else 'unknown'
    if not store.throttle('peer:'+peer) or not store.throttle('account:'+body.username.strip().lower()):
        raise HTTPException(429, 'Too many attempts. Try again in one minute.', headers={'Retry-After':'60'})
    token = store.login(body.username,body.password)
    if not token:
        raise HTTPException(401, 'Invalid username or password.')
    store.revoke(store.token_from(request))
    response.set_cookie(store.COOKIE, token, httponly=True, secure=get_settings().session_cookie_secure, samesite='strict', max_age=3600)
    response.delete_cookie('ecdat_guest_id')
    return {'authenticated': True, 'user': store.resolve(token)}

@router.delete('/session')
def logout(request: Request, response: Response):
    store.revoke(store.token_from(request))
    response.delete_cookie(store.COOKIE)
    response.delete_cookie('ecdat_guest_id')
    return {'authenticated': False}

class NewUser(BaseModel):
    model_config = ConfigDict(extra='forbid')
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=15, max_length=128)

class UserUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    password: str | None = Field(default=None, min_length=15, max_length=128)
    active: bool | None = None

@router.get('/admin/users')
def users(admin: AdminUser):
    return store.list_users()

@router.post('/admin/users', status_code=201)
def add_user(body: NewUser, admin: AdminUser):
    try:
        ident = store.create_user(body.username, body.password)
    except sqlite3.IntegrityError:
        raise HTTPException(409, 'Username already exists.') from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return {'id': ident, 'username': store.username(body.username), 'role': 'user', 'active': True, 'source': 'local'}

@router.patch('/admin/users/{user_id}')
def update_user(user_id: uuid.UUID, body: UserUpdate, admin: AdminUser):
    if body.password is None and body.active is None:
        raise HTTPException(422, 'Provide a password or active state.')
    try:
        store.manage_user(user_id, password=body.password, active=body.active)
    except LookupError:
        raise HTTPException(404, 'Account not found.') from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return {'updated': True}

async def guard(request: Request, call_next):
    path = request.url.path
    if request.method not in {'GET','HEAD','OPTIONS'}:
        origin = request.headers.get('origin')
        if (origin and origin not in get_settings().cors_origins) or request.headers.get('sec-fetch-site') == 'cross-site':
            return JSONResponse({'detail':'Request origin is not allowed.'}, status_code=403)
    protected = path.startswith('/api/') or path in {'/docs','/redoc','/openapi.json'}
    public = path in {'/api/v1/session','/api/v1/health','/api/v1/ready'}
    if protected and not public and request.method != 'OPTIONS':
        from starlette.concurrency import run_in_threadpool
        if not await run_in_threadpool(store.resolve, store.token_from(request)):
            return JSONResponse({'detail':'Sign in required.'}, status_code=401)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    if protected:
        response.headers['Cache-Control'] = 'no-store'
    return response


class RequestSizeLimit:
    """Bound streamed bodies before Starlette spools multipart input to disk."""

    def __init__(self, app, max_bytes: int = 501 * 1024 * 1024):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        limit = self.max_bytes if path.rstrip("/") == "/api/v1/uploads" else 1024 * 1024
        headers = dict(scope.get("headers", []))

        try:
            declared = int(headers.get(b"content-length", b"0"))
            if declared < 0:
                raise ValueError()
        except ValueError:
            return await JSONResponse(
                {"detail": "Invalid Content-Length."}, status_code=400
            )(scope, receive, send)

        if declared > limit:
            return await JSONResponse(
                {"detail": "Request body exceeds the maximum allowed size."},
                status_code=413,
            )(scope, receive, send)

        received_bytes, exceeded, sent = 0, False, False

        async def limited_receive():
            nonlocal received_bytes, exceeded
            message = await receive()
            received_bytes += len(message.get('body', b''))
            if received_bytes > limit:
                exceeded = True
                raise HTTPException(413, 'Request body exceeds the maximum allowed size.')
            return message

        async def limited_send(message):
            nonlocal sent
            if exceeded:
                if not sent:
                    sent = True
                    await JSONResponse({'detail': 'Request body exceeds the maximum allowed size.'}, status_code=413)(scope, receive, send)
                return
            if message['type'] == 'http.response.start':
                sent = True
            await send(message)

        await self.app(scope, limited_receive, limited_send)
