"""
TazoSploit SaaS v2 - Authentication Module
JWT-based authentication with multi-tenant support
"""

import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .database import get_db

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class TokenData(BaseModel):
    user_id: str
    tenant_id: str
    email: str
    role: str

class CurrentUser(BaseModel):
    id: str
    tenant_id: str
    email: str
    role: str

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenData(
            user_id=payload.get("sub"),
            tenant_id=payload.get("tenant_id"),
            email=payload.get("email"),
            role=payload.get("role", "viewer")
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

INTERNAL_SERVICE_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> CurrentUser:
    """Get current authenticated user"""
    token = credentials.credentials
    
    # Allow internal service auth (for worker -> control-plane)
    if token == f"internal-{INTERNAL_SERVICE_KEY}":
        return CurrentUser(
            id="b0000000-0000-0000-0000-000000000001",
            tenant_id="a0000000-0000-0000-0000-000000000001",
            email="system@tazosploit.local",
            role="admin"
        )
    
    token_data = decode_token(token)
    
    return CurrentUser(
        id=token_data.user_id,
        tenant_id=token_data.tenant_id,
        email=token_data.email,
        role=token_data.role
    )

def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(func):
        async def wrapper(*args, current_user: CurrentUser = Depends(get_current_user), **kwargs):
            # Simple role-based check
            role_permissions = {
                "admin": ["*"],
                "operator": ["jobs:create", "jobs:read", "scopes:read"],
                "viewer": ["jobs:read", "scopes:read"],
                "auditor": ["audit:read", "jobs:read"]
            }
            
            user_perms = role_permissions.get(current_user.role, [])
            if "*" not in user_perms and permission not in user_perms:
                raise HTTPException(status_code=403, detail="Permission denied")
            
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator
