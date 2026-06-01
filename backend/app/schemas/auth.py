from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    """Register a new user account."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    """Authenticate an existing user."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=8)


class RefreshTokenRequest(BaseModel):
    """Refresh an expired access token with a refresh token."""

    model_config = ConfigDict(extra="forbid")

    refresh_token: str


class TokenResponse(BaseModel):
    """Authentication token payload."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class ProtectedResponse(BaseModel):
    """Protected route response payload."""

    message: str
    subject: str
