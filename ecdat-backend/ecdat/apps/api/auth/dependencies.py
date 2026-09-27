"""Authenticated identities only; caller-supplied guest IDs never grant access."""
import uuid
from dataclasses import dataclass
from typing import Annotated
from fastapi import Depends, HTTPException, Request
from ecdat.apps.api.auth.store import resolve, token_from

@dataclass
class WorkspaceUser:
    id: uuid.UUID
    username: str
    role: str = "user"


def get_current_user(request: Request) -> WorkspaceUser:
    user = resolve(token_from(request))
    if not user:
        raise HTTPException(401, 'Sign in required.')
    return WorkspaceUser(id=uuid.UUID(user['id']), username=user['username'], role=user['role'])

CurrentUser = Annotated[WorkspaceUser, Depends(get_current_user)]


def get_admin_user(user: CurrentUser) -> WorkspaceUser:
    if user.role != 'admin':
        raise HTTPException(403, 'Administrator access required.')
    return user

AdminUser = Annotated[WorkspaceUser, Depends(get_admin_user)]
