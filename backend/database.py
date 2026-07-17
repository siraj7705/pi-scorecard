import os
import asyncpg
from typing import Optional

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/pi_scorecard"
)

_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    return _pool


async def close_pool():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def init_db():
    """Run schema.sql to create tables if they don't exist."""
    pool = await get_pool()
    schema_path = os.path.join(os.path.dirname(__file__), "..", "..", "database", "schema.sql")
    with open(schema_path) as f:
        sql = f.read()
    async with pool.acquire() as conn:
        await conn.execute(sql)
    print("Database initialised.")
