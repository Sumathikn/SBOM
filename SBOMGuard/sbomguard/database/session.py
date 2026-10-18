"""
SBOMGuard Database Session & Connection Pooling
Configures SQLAlchemy 2.0 async engine with connection pooling and
graceful fallback for local development without running Docker containers.
"""
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import select
from config.settings import (
    DATABASE_URL,
    DB_POOL_SIZE,
    DB_MAX_OVERFLOW,
    DB_POOL_TIMEOUT,
    DB_POOL_RECYCLE,
    DATA_DIR,
)
from sbomguard.database.models import Base, ProjectModel

logger = logging.getLogger("sbomguard.database")

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None
_is_fallback = False


def _create_engine_instance(url: str, is_sqlite: bool) -> AsyncEngine:
    if is_sqlite:
        return create_async_engine(
            url,
            connect_args={"check_same_thread": False},
            echo=False,
        )
    return create_async_engine(
        url,
        pool_size=DB_POOL_SIZE,
        max_overflow=DB_MAX_OVERFLOW,
        pool_timeout=DB_POOL_TIMEOUT,
        pool_recycle=DB_POOL_RECYCLE,
        pool_pre_ping=True,
        echo=False,
    )


def get_engine() -> AsyncEngine:
    global _engine, _is_fallback
    if _engine is None:
        db_url = DATABASE_URL
        is_sq = "sqlite" in db_url
        _engine = _create_engine_instance(db_url, is_sq)
    return _engine


def switch_to_fallback():
    """Switch active engine to local SQLite storage."""
    global _engine, _session_factory, _is_fallback
    fallback_path = DATA_DIR / "sbomguard_v2.db"
    fallback_url = f"sqlite+aiosqlite:///{fallback_path}"
    logger.warning(
        f"⚠️ Switching database engine to local fallback: {fallback_url}. "
        f"Launch PostgreSQL via 'docker compose up -d' for production PostgreSQL 16."
    )
    _engine = _create_engine_instance(fallback_url, True)
    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    _is_fallback = True


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Async session context manager."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with get_db_context() as session:
        yield session


async def init_database():
    """Initialize database tables and ensure default project exists."""
    global _is_fallback
    try:
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        err = str(e).lower()
        if not _is_fallback and any(
            x in err
            for x in (
                "connection refused",
                "role",
                "does not exist",
                "password authentication",
                "cannot connect",
                "could not connect",
            )
        ):
            switch_to_fallback()
            engine = get_engine()
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        else:
            raise

    try:
        async with get_db_context() as session:
            res = await session.execute(
                select(ProjectModel).where(ProjectModel.id == "default")
            )
            if not res.scalar_one_or_none():
                session.add(
                    ProjectModel(
                        id="default",
                        name="Default Project",
                        description="Global workspace for supply chain security audits",
                    )
                )
    except Exception as e:
        logger.debug(f"Default project check: {e}")
