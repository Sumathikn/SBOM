"""
Unit tests for SQLite to PostgreSQL migration script
"""
import pytest
import sqlite3
import json
from pathlib import Path
from unittest.mock import patch

from sbomguard.database.migrate_sqlite import migrate_data


class TestMigrateSQLite:
    @pytest.mark.asyncio
    async def test_migrate_data_no_file(self, tmp_path):
        with patch("sbomguard.database.migrate_sqlite.SQLITE_PATH", tmp_path / "missing.db"):
            # Should gracefully return without error
            await migrate_data()

    @pytest.mark.asyncio
    async def test_migrate_data_with_records(self, tmp_path):
        db_path = tmp_path / "test_legacy.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE sboms (id TEXT PRIMARY KEY, sbom_data TEXT)")
        conn.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, scan_data TEXT)")

        sbom_record = {"id": "legacy-sbom-1", "name": "legacy-project", "components": []}
        scan_record = {
            "id": "legacy-scan-1",
            "sbom_id": "legacy-sbom-1",
            "total_components": 0,
            "total_vulnerabilities": 0,
            "overall_risk_score": 0.0,
        }

        conn.execute("INSERT INTO sboms VALUES (?, ?)", ("legacy-sbom-1", json.dumps(sbom_record)))
        conn.execute("INSERT INTO scans VALUES (?, ?)", ("legacy-scan-1", json.dumps(scan_record)))
        conn.commit()
        conn.close()

        with patch("sbomguard.database.migrate_sqlite.SQLITE_PATH", db_path):
            await migrate_data()
