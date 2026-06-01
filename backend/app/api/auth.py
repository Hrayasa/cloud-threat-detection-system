from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import User
from app.schemas.auth import (
    LoginRequest,
    ProtectedResponse,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
)
from app.services.auth_service import auth_service, get_current_token_payload

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: RegisterRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Register a new user account and issue tokens."""

    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        email=payload.email,
        hashed_password=auth_service.hash_password(payload.password),
        role="user",
        is_active=True,
    )

    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered") from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to register user") from exc

    access_token = auth_service.create_access_token(
        subject=user.email,
        additional_claims={"user_id": str(user.id), "role": user.role},
    )
    refresh_token = auth_service.create_refresh_token(
        subject=user.email,
        additional_claims={"user_id": str(user.id), "role": user.role},
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=auth_service.access_token_ttl_seconds,
    )


@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def login_user(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Authenticate a user and issue tokens."""

    user = db.query(User).filter(User.email == payload.email).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not auth_service.verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = auth_service.create_access_token(
        subject=user.email,
        additional_claims={"user_id": str(user.id), "role": user.role},
    )
    refresh_token = auth_service.create_refresh_token(
        subject=user.email,
        additional_claims={"user_id": str(user.id), "role": user.role},
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=auth_service.access_token_ttl_seconds,
    )


@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
def refresh_access_token(payload: RefreshTokenRequest) -> TokenResponse:
    """Issue a new access token from a valid refresh token."""

    token_claims = auth_service.decode_token(payload.refresh_token)
    if token_claims.token_type != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    additional_claims = {
        key: value
        for key, value in token_claims.payload.items()
        if key not in {"iat", "exp", "jti", "sub", "token_type"}
    }

    access_token = auth_service.create_access_token(
        subject=token_claims.subject,
        additional_claims=additional_claims,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=payload.refresh_token,
        token_type="bearer",
        expires_in=auth_service.access_token_ttl_seconds,
    )


@router.get("/me", response_model=ProtectedResponse, status_code=status.HTTP_200_OK)
def protected_route(token_claims=Depends(get_current_token_payload)) -> ProtectedResponse:
    """Example protected endpoint requiring a valid access token."""

    return ProtectedResponse(message="Access granted", subject=token_claims.subject)
