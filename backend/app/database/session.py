from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.core.config import settings


Base = declarative_base()


class DatabaseSessionManager:
    """Manage SQLAlchemy engine and session factory setup."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

        self._engine = create_engine(
            self._database_url,
            echo=False,
            future=True,
            pool_pre_ping=True,
        )

        self._session_factory = sessionmaker(
            bind=self._engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
            class_=Session,
        )

    @property
    def engine(self):
        """Return the configured SQLAlchemy engine."""

        return self._engine

    @property
    def session_factory(self):
        """Return the configured SQLAlchemy session factory."""

        return self._session_factory

    def create_session(self) -> Session:
        """Create and return a new database session."""

        return self._session_factory()

    def dispose(self) -> None:
        """Dispose database engine connections."""

        self._engine.dispose()

    def health_check(self) -> None:
        """Run a lightweight database connectivity check."""

        try:
            with self._engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError as exc:
            raise RuntimeError("Database health check failed") from exc


database_session_manager = DatabaseSessionManager(
    database_url=settings.database_url,
)

SessionLocal = database_session_manager.session_factory


def get_db() -> Generator[Session, None, None]:
    """Yield a database session for FastAPI dependency injection."""

    database_session = database_session_manager.create_session()

    try:
        yield database_session

    except SQLAlchemyError:
        database_session.rollback()
        raise

    finally:
        database_session.close()


def shutdown_database() -> None:
    """Dispose pooled database connections during shutdown."""

    database_session_manager.dispose()


# IMPORTANT:
# Import models BEFORE create_all()
# so SQLAlchemy knows which tables to create.

from app.models.alert import Alert
from app.models.user import User

print("Registered tables:", Base.metadata.tables.keys())

Base.metadata.create_all(bind=database_session_manager.engine)


__all__ = [
    "Base",
    "DatabaseSessionManager",
    "SessionLocal",
    "get_db",
    "shutdown_database",
]