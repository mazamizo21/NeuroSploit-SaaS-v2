"""
TazoSploit SaaS v2 - Auth Router
Login, token refresh, and user info
"""

from datetime import timedelta
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database import get_db
from ..models import User
from ..auth import (
    verify_password, create_access_token, get_current_user,
    CurrentUser, ACCESS_TOKEN_EXPIRE_MINUTES
)

router = APIRouter()


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60


class UserInfoResponse(BaseModel):
    id: str
    email: str
    full_name: str | None
    role: str
    tenant_id: str


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate and get JWT token"""
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalars().first()

    if not user or not user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    token = create_access_token(
        data={
            "sub": str(user.id),
            "tenant_id": str(user.tenant_id),
            "email": user.email,
            "role": user.role,
        },
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserInfoResponse)
async def get_me(current_user: CurrentUser = Depends(get_current_user)):
    """Get current user info"""
    return UserInfoResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=None,
        role=current_user.role,
        tenant_id=current_user.tenant_id,
    )
