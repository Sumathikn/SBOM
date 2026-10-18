"""
SBOMGuard Database Repository Layer
Provides async and sync CRUD operations for SBOMs, Components, Scans,
and Vulnerabilities using SQLAlchemy 2.0.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from sqlalchemy import select, func, desc, delete, and_
from sqlalchemy.ext.asyncio import AsyncSession

from sbomguard.database.session import get_db_context
from sbomguard.database.models import (
    SBOMModel,
    ComponentModel,
    ScanModel,
    VulnerabilityRecordModel,
    ProjectModel,
)

logger = logging.getLogger("sbomguard.repository")


# ─── Helper for Synchronous Callers ──────────────────────────────────────────

from sbomguard.database.session import init_database, switch_to_fallback

def _run_async(fn, *args, **kwargs):
    """Run an async coroutine callable from synchronous caller with resilient fallback."""
    def _execute():
        return asyncio.run(fn(*args, **kwargs))

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            try:
                return executor.submit(_execute).result()
            except Exception as e:
                err = str(e).lower()
                if any(
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
                    executor.submit(lambda: asyncio.run(init_database())).result()
                    return executor.submit(_execute).result()
                raise
    else:
        try:
            return _execute()
        except Exception as e:
            err = str(e).lower()
            if any(
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
                asyncio.run(init_database())
                return _execute()
            raise


# ─── SBOM Operations ────────────────────────────────────────────────────────

async def save_sbom_async(sbom_dict: dict, tenant_id: str = "default") -> str:
    """Save an SBOM and its components to PostgreSQL asynchronously."""
    async with get_db_context() as session:
        sbom_id = sbom_dict["id"]

        # Ensure project exists
        proj_res = await session.execute(
            select(ProjectModel).where(ProjectModel.id == tenant_id)
        )
        if not proj_res.scalar_one_or_none():
            session.add(
                ProjectModel(
                    id=tenant_id,
                    name=f"Project {tenant_id}",
                    description="Auto-generated project container",
                )
            )
            await session.flush()

        # Check existing SBOM to update or insert
        res = await session.execute(
            select(SBOMModel).where(
                and_(SBOMModel.id == sbom_id, SBOMModel.project_id == tenant_id)
            )
        )
        existing = res.scalar_one_or_none()

        created_str = sbom_dict.get("created_at")
        created_dt = (
            datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            if created_str
            else datetime.now(timezone.utc)
        )

        if existing:
            existing.name = sbom_dict.get("name", "")
            existing.version = sbom_dict.get("version", "1")
            existing.format = sbom_dict.get("format", "cyclonedx")
            existing.source_file = sbom_dict.get("source_file", "")
            existing.manifest_type = sbom_dict.get("manifest_type")
            existing.component_count = sbom_dict.get("component_count", 0)
            existing.quality_score = float(sbom_dict.get("quality_score", 0.0))
            existing.sbom_data = sbom_dict
            existing.updated_at = datetime.now(timezone.utc)
            # Remove existing components for re-population
            await session.execute(
                delete(ComponentModel).where(ComponentModel.sbom_id == sbom_id)
            )
        else:
            new_sbom = SBOMModel(
                id=sbom_id,
                project_id=tenant_id,
                name=sbom_dict.get("name", ""),
                version=sbom_dict.get("version", "1"),
                format=sbom_dict.get("format", "cyclonedx"),
                source_file=sbom_dict.get("source_file", ""),
                manifest_type=sbom_dict.get("manifest_type"),
                component_count=sbom_dict.get("component_count", 0),
                quality_score=float(sbom_dict.get("quality_score", 0.0)),
                sbom_data=sbom_dict,
                created_at=created_dt,
                updated_at=datetime.now(timezone.utc),
            )
            session.add(new_sbom)

        await session.flush()

        # Add individual components with indexes
        for comp in sbom_dict.get("components", []):
            comp_record = ComponentModel(
                sbom_id=sbom_id,
                project_id=tenant_id,
                name=comp["name"],
                version=comp.get("version", "unknown"),
                type=comp.get("type", "library"),
                purl=comp.get("purl"),
                ecosystem=comp.get("ecosystem"),
                license=comp.get("license"),
                is_direct=bool(comp.get("is_direct", True)),
                depth=int(comp.get("depth", 0)),
            )
            session.add(comp_record)

        return sbom_id


def save_sbom(sbom_dict: dict, tenant_id: str = "default") -> str:
    """Synchronous interface to save an SBOM."""
    return _run_async(save_sbom_async, sbom_dict, tenant_id)


async def get_sbom_async(sbom_id: str, tenant_id: str = "default") -> Optional[dict]:
    """Retrieve an SBOM by ID asynchronously."""
    async with get_db_context() as session:
        res = await session.execute(
            select(SBOMModel.sbom_data).where(
                and_(SBOMModel.id == sbom_id, SBOMModel.project_id == tenant_id)
            )
        )
        data = res.scalar_one_or_none()
        return data


def get_sbom(sbom_id: str, tenant_id: str = "default") -> Optional[dict]:
    """Synchronous interface to get an SBOM."""
    return _run_async(get_sbom_async, sbom_id, tenant_id)


async def list_sboms_async(limit: int = 50, tenant_id: str = "default") -> List[dict]:
    """List metadata for stored SBOMs asynchronously."""
    async with get_db_context() as session:
        query = (
            select(
                SBOMModel.id,
                SBOMModel.name,
                SBOMModel.format,
                SBOMModel.source_file,
                SBOMModel.manifest_type,
                SBOMModel.component_count,
                SBOMModel.quality_score,
                SBOMModel.created_at,
            )
            .where(SBOMModel.project_id == tenant_id)
            .order_by(desc(SBOMModel.created_at))
            .limit(limit)
        )
        res = await session.execute(query)
        rows = res.all()
        return [
            {
                "id": r.id,
                "name": r.name,
                "format": r.format,
                "source_file": r.source_file,
                "manifest_type": r.manifest_type,
                "component_count": r.component_count,
                "quality_score": r.quality_score,
                "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at),
            }
            for r in rows
        ]


def list_sboms(limit: int = 50, tenant_id: str = "default") -> List[dict]:
    """Synchronous interface to list SBOMs."""
    return _run_async(list_sboms_async, limit, tenant_id)


async def delete_sbom_async(sbom_id: str, tenant_id: str = "default") -> bool:
    """Delete an SBOM and its cascaded relations asynchronously."""
    async with get_db_context() as session:
        res = await session.execute(
            delete(SBOMModel).where(
                and_(SBOMModel.id == sbom_id, SBOMModel.project_id == tenant_id)
            )
        )
        return (res.rowcount or 0) > 0


def delete_sbom(sbom_id: str, tenant_id: str = "default") -> bool:
    """Synchronous interface to delete an SBOM."""
    return _run_async(delete_sbom_async, sbom_id, tenant_id)


# ─── Scan Operations ────────────────────────────────────────────────────────

async def save_scan_async(scan_dict: dict, tenant_id: str = "default") -> str:
    """Save a scan result and associated vulnerabilities asynchronously."""
    async with get_db_context() as session:
        scan_id = scan_dict["id"]
        sbom_id = scan_dict["sbom_id"]

        scanned_str = scan_dict.get("scanned_at")
        scanned_dt = (
            datetime.fromisoformat(scanned_str.replace("Z", "+00:00"))
            if scanned_str
            else datetime.now(timezone.utc)
        )

        res = await session.execute(
            select(ScanModel).where(
                and_(ScanModel.id == scan_id, ScanModel.project_id == tenant_id)
            )
        )
        existing = res.scalar_one_or_none()

        overall_lvl = scan_dict.get("overall_risk_level", "info")
        if hasattr(overall_lvl, "value"):
            overall_lvl = overall_lvl.value

        if existing:
            existing.sbom_id = sbom_id
            existing.sbom_name = scan_dict.get("sbom_name", "")
            existing.total_components = scan_dict.get("total_components", 0)
            existing.components_scanned = scan_dict.get("components_scanned", 0)
            existing.total_vulnerabilities = scan_dict.get("total_vulnerabilities", 0)
            existing.critical_count = scan_dict.get("critical_count", 0)
            existing.high_count = scan_dict.get("high_count", 0)
            existing.medium_count = scan_dict.get("medium_count", 0)
            existing.low_count = scan_dict.get("low_count", 0)
            existing.overall_risk_level = str(overall_lvl)
            existing.overall_risk_score = float(scan_dict.get("overall_risk_score", 0.0))
            existing.scan_data = scan_dict
            await session.execute(
                delete(VulnerabilityRecordModel).where(VulnerabilityRecordModel.scan_id == scan_id)
            )
        else:
            new_scan = ScanModel(
                id=scan_id,
                project_id=tenant_id,
                sbom_id=sbom_id,
                sbom_name=scan_dict.get("sbom_name", ""),
                total_components=scan_dict.get("total_components", 0),
                components_scanned=scan_dict.get("components_scanned", 0),
                total_vulnerabilities=scan_dict.get("total_vulnerabilities", 0),
                critical_count=scan_dict.get("critical_count", 0),
                high_count=scan_dict.get("high_count", 0),
                medium_count=scan_dict.get("medium_count", 0),
                low_count=scan_dict.get("low_count", 0),
                overall_risk_level=str(overall_lvl),
                overall_risk_score=float(scan_dict.get("overall_risk_score", 0.0)),
                scan_data=scan_dict,
                scanned_at=scanned_dt,
            )
            session.add(new_scan)

        await session.flush()

        # Add individual vulnerability records
        for ra in scan_dict.get("risk_assessments", []):
            comp_label = f"{ra.get('component_name')}@{ra.get('component_version')}"
            for v in ra.get("vulnerabilities", []):
                sev = v.get("severity", "none")
                if hasattr(sev, "value"):
                    sev = sev.value

                vuln_record = VulnerabilityRecordModel(
                    scan_id=scan_id,
                    project_id=tenant_id,
                    vuln_id=v.get("id", "UNKNOWN"),
                    source=v.get("source", "osv"),
                    title=v.get("title", ""),
                    description=v.get("description", ""),
                    severity=str(sev).lower(),
                    cvss_score=float(v.get("cvss_score", 0.0)),
                    epss_score=float(v.get("epss_score", 0.0)),
                    affected_component=v.get("affected_component") or comp_label,
                    fixed_version=v.get("fixed_version"),
                    exploit_available=bool(v.get("exploit_available", False)),
                    in_kev=bool(v.get("in_kev", False)),
                )
                session.add(vuln_record)

        return scan_id


def save_scan(scan_dict: dict, tenant_id: str = "default") -> str:
    """Synchronous interface to save a scan."""
    return _run_async(save_scan_async, scan_dict, tenant_id)


async def get_scan_async(scan_id: str, tenant_id: str = "default") -> Optional[dict]:
    """Retrieve a scan by ID asynchronously."""
    async with get_db_context() as session:
        res = await session.execute(
            select(ScanModel.scan_data).where(
                and_(ScanModel.id == scan_id, ScanModel.project_id == tenant_id)
            )
        )
        return res.scalar_one_or_none()


def get_scan(scan_id: str, tenant_id: str = "default") -> Optional[dict]:
    """Synchronous interface to get a scan."""
    return _run_async(get_scan_async, scan_id, tenant_id)


async def list_scans_async(limit: int = 50, tenant_id: str = "default") -> List[dict]:
    """List metadata for scans asynchronously."""
    async with get_db_context() as session:
        query = (
            select(
                ScanModel.id,
                ScanModel.sbom_id,
                ScanModel.sbom_name,
                ScanModel.total_components,
                ScanModel.total_vulnerabilities,
                ScanModel.critical_count,
                ScanModel.high_count,
                ScanModel.medium_count,
                ScanModel.low_count,
                ScanModel.overall_risk_level,
                ScanModel.overall_risk_score,
                ScanModel.scanned_at,
            )
            .where(ScanModel.project_id == tenant_id)
            .order_by(desc(ScanModel.scanned_at))
            .limit(limit)
        )
        res = await session.execute(query)
        rows = res.all()
        return [
            {
                "id": r.id,
                "sbom_id": r.sbom_id,
                "sbom_name": r.sbom_name,
                "total_components": r.total_components,
                "total_vulnerabilities": r.total_vulnerabilities,
                "critical_count": r.critical_count,
                "high_count": r.high_count,
                "medium_count": r.medium_count,
                "low_count": r.low_count,
                "overall_risk_level": r.overall_risk_level,
                "overall_risk_score": r.overall_risk_score,
                "scanned_at": r.scanned_at.isoformat() if hasattr(r.scanned_at, "isoformat") else str(r.scanned_at),
            }
            for r in rows
        ]


def list_scans(limit: int = 50, tenant_id: str = "default") -> List[dict]:
    """Synchronous interface to list scans."""
    return _run_async(list_scans_async, limit, tenant_id)


# ─── Dashboard Aggregations ─────────────────────────────────────────────────

async def get_dashboard_stats_async(tenant_id: str = "default") -> dict:
    """Compute aggregated dashboard telemetry from PostgreSQL asynchronously."""
    async with get_db_context() as session:
        # 1. Counts
        sbom_count = (
            await session.execute(
                select(func.count(SBOMModel.id)).where(SBOMModel.project_id == tenant_id)
            )
        ).scalar() or 0

        comp_count = (
            await session.execute(
                select(func.count(ComponentModel.id)).where(ComponentModel.project_id == tenant_id)
            )
        ).scalar() or 0

        scan_count = (
            await session.execute(
                select(func.count(ScanModel.id)).where(ScanModel.project_id == tenant_id)
            )
        ).scalar() or 0

        # 2. Vulnerability severities
        vuln_counts_query = select(
            func.count(VulnerabilityRecordModel.id).label("total"),
            func.sum(case_col(VulnerabilityRecordModel.severity == "critical", 1, 0)).label("critical"),
            func.sum(case_col(VulnerabilityRecordModel.severity == "high", 1, 0)).label("high"),
            func.sum(case_col(VulnerabilityRecordModel.severity == "medium", 1, 0)).label("medium"),
            func.sum(case_col(VulnerabilityRecordModel.severity == "low", 1, 0)).label("low"),
        ).where(VulnerabilityRecordModel.project_id == tenant_id)

        v_res = (await session.execute(vuln_counts_query)).one()
        total_vulns = v_res.total or 0
        critical_v = v_res.critical or 0
        high_v = v_res.high or 0
        medium_v = v_res.medium or 0
        low_v = v_res.low or 0

        # 3. Average risk score
        avg_risk_res = (
            await session.execute(
                select(func.avg(ScanModel.overall_risk_score)).where(ScanModel.project_id == tenant_id)
            )
        ).scalar()
        avg_risk = float(avg_risk_res) if avg_risk_res is not None else 0.0

        # 4. Recent SBOMs
        recent_sboms = await list_sboms_async(limit=5, tenant_id=tenant_id)

        # 5. Recent scans
        recent_scans = await list_scans_async(limit=5, tenant_id=tenant_id)

        # 6. Top vulnerable components
        top_vuln_query = (
            select(
                VulnerabilityRecordModel.affected_component,
                func.count(VulnerabilityRecordModel.id).label("vuln_count"),
                func.max(VulnerabilityRecordModel.cvss_score).label("max_cvss"),
            )
            .where(VulnerabilityRecordModel.project_id == tenant_id)
            .group_by(VulnerabilityRecordModel.affected_component)
            .order_by(desc("vuln_count"))
            .limit(10)
        )
        top_vuln_rows = (await session.execute(top_vuln_query)).all()
        top_vulns = [
            {
                "affected_component": r.affected_component,
                "vuln_count": r.vuln_count,
                "max_cvss": r.max_cvss,
            }
            for r in top_vuln_rows
        ]

        # 7. Ecosystem distribution
        eco_query = (
            select(
                func.coalesce(ComponentModel.ecosystem, "other").label("eco"),
                func.count(ComponentModel.id).label("count"),
            )
            .where(ComponentModel.project_id == tenant_id)
            .group_by("eco")
            .order_by(desc("count"))
        )
        eco_rows = (await session.execute(eco_query)).all()
        ecosystem_dist = {r.eco: r.count for r in eco_rows}

        # 8. Dependency direct vs transitive ratio
        direct_count = (
            await session.execute(
                select(func.count(ComponentModel.id)).where(
                    and_(ComponentModel.project_id == tenant_id, ComponentModel.is_direct == True)
                )
            )
        ).scalar() or 0

        transitive_count = (
            await session.execute(
                select(func.count(ComponentModel.id)).where(
                    and_(ComponentModel.project_id == tenant_id, ComponentModel.is_direct == False)
                )
            )
        ).scalar() or 0

        # 9. Recent timeline points
        timeline_query = (
            select(
                func.date(ScanModel.scanned_at).label("scan_date"),
                func.sum(ScanModel.total_vulnerabilities).label("vulns"),
                func.count(ScanModel.id).label("scans"),
            )
            .where(ScanModel.project_id == tenant_id)
            .group_by("scan_date")
            .order_by(desc("scan_date"))
            .limit(7)
        )
        t_rows = (await session.execute(timeline_query)).all()
        timeline = [
            {"scan_date": str(r.scan_date), "vulns": int(r.vulns or 0), "scans": int(r.scans or 0)}
            for r in reversed(t_rows)
        ]

        return {
            "total_sboms": sbom_count,
            "total_components": comp_count,
            "total_scans": scan_count,
            "total_vulnerabilities": total_vulns,
            "critical_vulns": critical_v,
            "high_vulns": high_v,
            "medium_vulns": medium_v,
            "low_vulns": low_v,
            "avg_risk_score": round(avg_risk, 1),
            "recent_sboms": recent_sboms,
            "recent_scans": recent_scans,
            "top_vulnerable_components": top_vulns,
            "severity_distribution": {
                "critical": critical_v,
                "high": high_v,
                "medium": medium_v,
                "low": low_v,
            },
            "ecosystem_distribution": ecosystem_dist,
            "dependency_ratio": {
                "direct": direct_count,
                "transitive": transitive_count,
            },
            "timeline": timeline,
        }


def case_col(criterion, val_true, val_false):
    """Helper to generate SQL CASE WHEN expression."""
    from sqlalchemy import case
    return case((criterion, val_true), else_=val_false)


def get_dashboard_stats(tenant_id: str = "default") -> dict:
    """Synchronous interface for dashboard statistics."""
    return _run_async(get_dashboard_stats_async, tenant_id)
