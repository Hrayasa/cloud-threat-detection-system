from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import uuid4

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError
from passlib.context import CryptContext

from app.core.config import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_scheme = HTTPBearer()


@dataclass(slots=True)
class TokenClaims:
    """Validated token claims returned after decoding."""

    subject: str
    token_type: Literal["access", "refresh"]
    payload: dict[str, Any]


class AuthenticationService:
    """Secure JWT authentication helper for FastAPI applications."""

    def __init__(
        self,
        secret_key: str,
        algorithm: str,
        access_token_expire_minutes: int,
        refresh_token_expire_days: int,
    ) -> None:
        if not secret_key:
            raise ValueError("JWT secret key must be configured")
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._access_token_expire_minutes = access_token_expire_minutes
        self._refresh_token_expire_days = refresh_token_expire_days

    @property
    def secret_key(self) -> str:
        """Return the configured signing key."""

        return self._secret_key

    @property
    def algorithm(self) -> str:
        """Return the configured JWT algorithm."""

        return self._algorithm

    @property
    def access_token_ttl_seconds(self) -> int:
        """Return the access token lifetime in seconds."""

        return self._access_token_expire_minutes * 60

    @property
    def refresh_token_ttl_seconds(self) -> int:
        """Return the refresh token lifetime in seconds."""

        return self._refresh_token_expire_days * 24 * 60 * 60

    def hash_password(self, password: str) -> str:
        """Hash a plain-text password with bcrypt."""

        return pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Validate a plain-text password against a bcrypt hash."""

        return pwd_context.verify(plain_password, hashed_password)

    def create_access_token(self, subject: str, additional_claims: dict[str, Any] | None = None) -> str:
        """Create a short-lived access token."""

        return self._create_token(
            subject=subject,
            token_type="access",
            expires_in=timedelta(minutes=self._access_token_expire_minutes),
            additional_claims=additional_claims,
        )

    def create_refresh_token(self, subject: str, additional_claims: dict[str, Any] | None = None) -> str:
        """Create a long-lived refresh token."""

        return self._create_token(
            subject=subject,
            token_type="refresh",
            expires_in=timedelta(days=self._refresh_token_expire_days),
            additional_claims=additional_claims,
        )

    def decode_token(self, token: str) -> TokenClaims:
        """Decode and validate a JWT token."""

        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        except ExpiredSignatureError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired") from exc
        except JWTError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

        token_type = payload.get("token_type")
        subject = payload.get("sub")
        if not isinstance(subject, str) or not isinstance(token_type, str):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")

        return TokenClaims(subject=subject, token_type=token_type, payload=payload)

    def _create_token(
        self,
        subject: str,
        token_type: Literal["access", "refresh"],
        expires_in: timedelta,
        additional_claims: dict[str, Any] | None,
    ) -> str:
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + expires_in

        payload: dict[str, Any] = {
            "sub": subject,
            "token_type": token_type,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(uuid4()),
        }

        if additional_claims:
            payload.update(additional_claims)

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)


auth_service = AuthenticationService(
    secret_key=settings.jwt_secret_key,
    algorithm=settings.jwt_algorithm,
    access_token_expire_minutes=settings.access_token_expire_minutes,
    refresh_token_expire_days=settings.refresh_token_expire_days,
)


async def get_current_token_payload(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> TokenClaims:
    """FastAPI dependency that extracts and validates the bearer token."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")

    token_claims = auth_service.decode_token(credentials.credentials)
    if token_claims.token_type != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    return token_claims


__all__ = [
    "AuthenticationService",
    "TokenClaims",
    "auth_service",
    "get_current_token_payload",
    "pwd_context",
]
