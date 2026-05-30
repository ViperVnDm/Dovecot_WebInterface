"""Database engine configuration tests."""

import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.database import _apply_sqlite_pragmas


@pytest.mark.asyncio
async def test_sqlite_pragmas_enable_wal_and_busy_timeout(tmp_path):
    """A connection wired with _apply_sqlite_pragmas runs in WAL with a timeout."""
    db_file = tmp_path / "pragmas.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_file}")
    event.listen(
        engine.sync_engine, "connect",
        lambda dbapi, record: _apply_sqlite_pragmas(dbapi),
    )
    try:
        async with engine.connect() as conn:
            mode = (await conn.execute(text("PRAGMA journal_mode"))).scalar()
            busy = (await conn.execute(text("PRAGMA busy_timeout"))).scalar()
    finally:
        await engine.dispose()

    assert mode.lower() == "wal"
    assert busy == 5000
