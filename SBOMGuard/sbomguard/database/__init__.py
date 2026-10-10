"""
SBOMGuard Database Layer
SQLite-based storage for SBOMs, scan results, and metadata.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config.settings import DB_PATH


def get_connection() -> sqlite3.Connection:
    """Create a new database connection."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database():
    """Initialize the database schema."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sboms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT DEFAULT '1',
                format TEXT DEFAULT 'cyclonedx',
                source_file TEXT,
                manifest_type TEXT,
                component_count INTEGER DEFAULT 0,
                quality_score REAL DEFAULT 0.0,
                sbom_data TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sbom_id TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                type TEXT DEFAULT 'library',
                purl TEXT,
                ecosystem TEXT,
                license TEXT,
                is_direct INTEGER DEFAULT 1,
                depth INTEGER DEFAULT 0,
                FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                sbom_id TEXT NOT NULL,
                sbom_name TEXT,
                total_components INTEGER DEFAULT 0,
                components_scanned INTEGER DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                overall_risk_level TEXT DEFAULT 'info',
                overall_risk_score REAL DEFAULT 0.0,
                scan_data TEXT,
                scanned_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                vuln_id TEXT NOT NULL,
                source TEXT,
                title TEXT,
                description TEXT,
                severity TEXT DEFAULT 'none',
                cvss_score REAL DEFAULT 0.0,
                epss_score REAL DEFAULT 0.0,
                affected_component TEXT,
                fixed_version TEXT,
                exploit_available INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_components_sbom ON components(sbom_id);
            CREATE INDEX IF NOT EXISTS idx_scans_sbom ON scans(sbom_id);
            CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
        """)
    print("✅ Database initialized successfully.")


# ─── SBOM CRUD Operations ───────────────────────────────────────────────────

def save_sbom(sbom_dict: dict) -> str:
    """Save an SBOM to the database. Returns the SBOM ID."""
    with get_db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO sboms
               (id, name, version, format, source_file, manifest_type,
                component_count, quality_score, sbom_data, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sbom_dict["id"],
                sbom_dict.get("name", ""),
                sbom_dict.get("version", "1"),
                sbom_dict.get("format", "cyclonedx"),
                sbom_dict.get("source_file", ""),
                sbom_dict.get("manifest_type"),
                sbom_dict.get("component_count", 0),
                sbom_dict.get("quality_score", 0.0),
                json.dumps(sbom_dict),
                sbom_dict.get("created_at", datetime.now(timezone.utc).isoformat()),
            ),
        )
        # Save individual components
        for comp in sbom_dict.get("components", []):
            conn.execute(
                """INSERT INTO components
                   (sbom_id, name, version, type, purl, ecosystem, license, is_direct, depth)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sbom_dict["id"],
                    comp["name"],
                    comp["version"],
                    comp.get("type", "library"),
                    comp.get("purl"),
                    comp.get("ecosystem"),
                    comp.get("license"),
                    1 if comp.get("is_direct", True) else 0,
                    comp.get("depth", 0),
                ),
            )
    return sbom_dict["id"]


def get_sbom(sbom_id: str) -> Optional[dict]:
    """Retrieve an SBOM by ID."""
    with get_db() as conn:
        row = conn.execute("SELECT sbom_data FROM sboms WHERE id = ?", (sbom_id,)).fetchone()
        if row:
            return json.loads(row["sbom_data"])
    return None


def list_sboms(limit: int = 50) -> list[dict]:
    """List all stored SBOMs (metadata only)."""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, name, format, source_file, manifest_type,
                      component_count, quality_score, created_at
               FROM sboms ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def delete_sbom(sbom_id: str) -> bool:
    """Delete an SBOM and its associated data."""
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM sboms WHERE id = ?", (sbom_id,))
        return cursor.rowcount > 0


# ─── Scan CRUD Operations ───────────────────────────────────────────────────

def save_scan(scan_dict: dict) -> str:
    """Save a scan result to the database."""
    with get_db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scans
               (id, sbom_id, sbom_name, total_components, components_scanned,
                total_vulnerabilities, critical_count, high_count, medium_count,
                low_count, overall_risk_level, overall_risk_score, scan_data, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_dict["id"],
                scan_dict["sbom_id"],
                scan_dict.get("sbom_name", ""),
                scan_dict.get("total_components", 0),
                scan_dict.get("components_scanned", 0),
                scan_dict.get("total_vulnerabilities", 0),
                scan_dict.get("critical_count", 0),
                scan_dict.get("high_count", 0),
                scan_dict.get("medium_count", 0),
                scan_dict.get("low_count", 0),
                scan_dict.get("overall_risk_level", "info"),
                scan_dict.get("overall_risk_score", 0.0),
                json.dumps(scan_dict),
                scan_dict.get("scanned_at", datetime.now(timezone.utc).isoformat()),
            ),
        )
        # Save individual vulnerabilities
        for ra in scan_dict.get("risk_assessments", []):
            for vuln in ra.get("vulnerabilities", []):
                conn.execute(
                    """INSERT INTO vulnerabilities
                       (scan_id, vuln_id, source, title, description, severity,
                        cvss_score, epss_score, affected_component, fixed_version,
                        exploit_available)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_dict["id"],
                        vuln.get("id", ""),
                        vuln.get("source", ""),
                        vuln.get("title", ""),
                        vuln.get("description", ""),
                        vuln.get("severity", "none"),
                        vuln.get("cvss_score", 0.0),
                        vuln.get("epss_score", 0.0),
                        vuln.get("affected_component", ""),
                        vuln.get("fixed_version"),
                        1 if vuln.get("exploit_available", False) else 0,
                    ),
                )
    return scan_dict["id"]


def get_scan(scan_id: str) -> Optional[dict]:
    """Retrieve a scan by ID."""
    with get_db() as conn:
        row = conn.execute("SELECT scan_data FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row:
            return json.loads(row["scan_data"])
    return None


def list_scans(limit: int = 50) -> list[dict]:
    """List all scan results (metadata only)."""
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, sbom_id, sbom_name, total_components,
                      total_vulnerabilities, critical_count, high_count,
                      medium_count, low_count, overall_risk_level,
                      overall_risk_score, scanned_at
               FROM scans ORDER BY scanned_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ─── Dashboard Queries ───────────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    """Get aggregated statistics for the dashboard."""
    with get_db() as conn:
        sbom_count = conn.execute("SELECT COUNT(*) as c FROM sboms").fetchone()["c"]
        comp_count = conn.execute("SELECT COUNT(*) as c FROM components").fetchone()["c"]
        scan_count = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]

        vuln_stats = conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) as low
            FROM vulnerabilities
        """).fetchone()

        avg_risk = conn.execute(
            "SELECT AVG(overall_risk_score) as avg FROM scans"
        ).fetchone()["avg"] or 0.0

        recent_sboms = conn.execute(
            """SELECT id, name, component_count, quality_score, created_at
               FROM sboms ORDER BY created_at DESC LIMIT 5"""
        ).fetchall()

        recent_scans = conn.execute(
            """SELECT id, sbom_name, total_vulnerabilities, overall_risk_level,
                      overall_risk_score, scanned_at
               FROM scans ORDER BY scanned_at DESC LIMIT 5"""
        ).fetchall()

        top_vulns = conn.execute(
            """SELECT affected_component, COUNT(*) as vuln_count,
                      MAX(cvss_score) as max_cvss
               FROM vulnerabilities
               GROUP BY affected_component
               ORDER BY vuln_count DESC LIMIT 10"""
        ).fetchall()

        # Ecosystem distribution
        eco_rows = conn.execute("""
            SELECT COALESCE(NULLIF(ecosystem, ''), 'other') as eco, COUNT(*) as count
            FROM components
            GROUP BY eco
            ORDER BY count DESC
        """).fetchall()
        ecosystem_dist = {r["eco"]: r["count"] for r in eco_rows}

        # Direct vs transitive dependency ratio
        dep_row = conn.execute("""
            SELECT
                SUM(CASE WHEN is_direct = 1 THEN 1 ELSE 0 END) as direct_count,
                SUM(CASE WHEN is_direct = 0 THEN 1 ELSE 0 END) as transitive_count
            FROM components
        """).fetchone()
        direct_count = (dep_row["direct_count"] or 0) if dep_row else 0
        transitive_count = (dep_row["transitive_count"] or 0) if dep_row else 0

        # Recent scan bar timeline points
        timeline_rows = conn.execute("""
            SELECT strftime('%m.%d', scanned_at) as scan_date,
                   SUM(total_vulnerabilities) as vulns,
                   COUNT(*) as scans
            FROM scans
            GROUP BY scan_date
            ORDER BY scanned_at DESC
            LIMIT 7
        """).fetchall()

        return {
            "total_sboms": sbom_count,
            "total_components": comp_count,
            "total_scans": scan_count,
            "total_vulnerabilities": vuln_stats["total"] or 0,
            "critical_vulns": vuln_stats["critical"] or 0,
            "high_vulns": vuln_stats["high"] or 0,
            "medium_vulns": vuln_stats["medium"] or 0,
            "low_vulns": vuln_stats["low"] or 0,
            "avg_risk_score": round(avg_risk, 1),
            "recent_sboms": [dict(r) for r in recent_sboms],
            "recent_scans": [dict(r) for r in recent_scans],
            "top_vulnerable_components": [dict(r) for r in top_vulns],
            "severity_distribution": {
                "critical": vuln_stats["critical"] or 0,
                "high": vuln_stats["high"] or 0,
                "medium": vuln_stats["medium"] or 0,
                "low": vuln_stats["low"] or 0,
            },
            "ecosystem_distribution": ecosystem_dist,
            "dependency_ratio": {
                "direct": direct_count,
                "transitive": transitive_count,
            },
            "timeline": [dict(r) for r in reversed(timeline_rows)],
        }
