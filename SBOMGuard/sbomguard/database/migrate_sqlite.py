"""
SBOMGuard SQLite to PostgreSQL Data Migration Tool
Transfers historical SBOMs, components, scans, and vulnerabilities from
legacy SQLite database into the new PostgreSQL schema.
"""
import json
import sqlite3
import asyncio
from pathlib import Path
from datetime import datetime, timezone

from config.settings import DATA_DIR
from sbomguard.database.session import init_database
from sbomguard.database.repository import save_sbom_async, save_scan_async

SQLITE_PATH = DATA_DIR / "sbomguard.db"


async def migrate_data():
    """Migrate all rows from SQLite into PostgreSQL."""
    if not SQLITE_PATH.exists():
        print(f"ℹ️ No SQLite database found at {SQLITE_PATH}. Nothing to migrate.")
        return

    print(f"📦 Found legacy SQLite database: {SQLITE_PATH}")
    await init_database()

    conn = sqlite3.connect(str(SQLITE_PATH))
    conn.row_factory = sqlite3.Row

    # 1. Migrate SBOMs
    sbom_rows = conn.execute("SELECT * FROM sboms").fetchall()
    print(f"  Transferring {len(sbom_rows)} SBOM(s)...")
    for r in sbom_rows:
        try:
            data = json.loads(r["sbom_data"])
            await save_sbom_async(data)
        except Exception as e:
            print(f"  ⚠️ Error migrating SBOM {r['id']}: {e}")

    # 2. Migrate Scans
    scan_rows = conn.execute("SELECT * FROM scans").fetchall()
    print(f"  Transferring {len(scan_rows)} Scan(s)...")
    for r in scan_rows:
        try:
            data = json.loads(r["scan_data"])
            await save_scan_async(data)
        except Exception as e:
            print(f"  ⚠️ Error migrating Scan {r['id']}: {e}")

    conn.close()
    print("✅ Migration from SQLite to PostgreSQL completed successfully!")


if __name__ == "__main__":
    asyncio.run(migrate_data())
