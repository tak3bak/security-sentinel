import os
import socket
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from .config import settings

db_url = settings().database_url

# Automatic fallback to local async SQLite if PostgreSQL is not listening
if "postgresql" in db_url and not os.getenv("FORCE_POSTGRES"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", 5432))
        s.close()
    except Exception:
        db_url = "sqlite+aiosqlite:///sentinel.db"

engine = create_async_engine(db_url, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

async def get_session():
    async with SessionLocal() as session:
        yield session
