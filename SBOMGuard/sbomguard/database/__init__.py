"""
SBOMGuard Database Layer
PostgreSQL + SQLAlchemy 2.0 async storage with connection pooling,
high-cardinality indexing, and multi-tenant isolation.
"""
from sbomguard.database.session import (
    get_engine,
    get_session_factory,
    get_db_context,
    get_async_session,
    init_database,
)
from sbomguard.database.models import (
    Base,
    ProjectModel,
    SBOMModel,
    ComponentModel,
    ScanModel,
    VulnerabilityRecordModel,
)
from sbomguard.database.repository import (
    save_sbom,
    save_sbom_async,
    get_sbom,
    get_sbom_async,
    list_sboms,
    list_sboms_async,
    delete_sbom,
    delete_sbom_async,
    save_scan,
    save_scan_async,
    get_scan,
    get_scan_async,
    list_scans,
    list_scans_async,
    get_dashboard_stats,
    get_dashboard_stats_async,
)

__all__ = [
    "get_engine",
    "get_session_factory",
    "get_db_context",
    "get_async_session",
    "init_database",
    "Base",
    "ProjectModel",
    "SBOMModel",
    "ComponentModel",
    "ScanModel",
    "VulnerabilityRecordModel",
    "save_sbom",
    "save_sbom_async",
    "get_sbom",
    "get_sbom_async",
    "list_sboms",
    "list_sboms_async",
    "delete_sbom",
    "delete_sbom_async",
    "save_scan",
    "save_scan_async",
    "get_scan",
    "get_scan_async",
    "list_scans",
    "list_scans_async",
    "get_dashboard_stats",
    "get_dashboard_stats_async",
]
