from __future__ import annotations

import logging
import os
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response

from app.api.auth import router as auth_router
from app.api.alerts import router as alerts_router
from app.api.logs import router as logs_router

from app.database.session import (
    database_session_manager,
    shutdown_database,
)

from app.services.auth_service import auth_service


logger = logging.getLogger("cloud-threat-detection-system")


def _parse_cors_origins() -> list[str]:
    raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
    if raw_origins.strip() == "*":
        return ["*"]
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Application startup initiated")
    try:
        database_session_manager.health_check()
    except RuntimeError:
        logger.exception("Database connectivity check failed during startup")
        raise
    else:
        logger.info("Database connectivity verified")

    yield

    logger.info("Application shutdown initiated")
    shutdown_database()


app = FastAPI(
    title="Cloud Threat Detection System",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_parse_cors_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def jwt_context_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    authorization = request.headers.get("authorization")
    request.state.auth_subject = None
    request.state.auth_token_type = None

    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            try:
                token_claims = auth_service.decode_token(token)
                request.state.auth_subject = token_claims.subject
                request.state.auth_token_type = token_claims.token_type
            except Exception as exc:  # noqa: BLE001
                request.state.auth_error = str(exc)

    response = await call_next(request)
    return response


@app.middleware("http")
async def structured_logging_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    logger.info(
        "request.completed",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "auth_subject": getattr(request.state, "auth_subject", None),
            "auth_token_type": getattr(request.state, "auth_token_type", None),
            "client_ip": request.client.host if request.client else None,
        },
    )
    return response


@app.middleware("http")
async def exception_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    try:
        response = await call_next(request)
        return response
    except Exception:  # noqa: BLE001
        logger.exception(
            "Unhandled exception",
            extra={
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host if request.client else None,
            },
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )


@app.get("/health")
def health_check() -> dict[str, Any]:
    """Return service and database health details."""

    response: dict[str, Any] = {
        "status": "ok",
        "service": "cloud-threat-detection-system",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        database_session_manager.health_check()
        response["database"] = "healthy"
    except RuntimeError:
        response["status"] = "degraded"
        response["database"] = "unavailable"

    return response

@app.get("/")
async def root() -> dict[str, str]:
    """
    Root endpoint for service availability checks.
    """

    return {
        "message": "Cloud Threat Detection System API Running",
    }

app.include_router(auth_router)
app.include_router(alerts_router)
app.include_router(logs_router)