"""initial schema with postgresql tables and indexes

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-10-18 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Projects (Tenancy)
    op.create_table(
        'projects',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # 2. SBOMs
    op.create_table(
        'sboms',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('project_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=64), nullable=False),
        sa.Column('format', sa.String(length=32), nullable=False),
        sa.Column('source_file', sa.String(length=512), nullable=True),
        sa.Column('manifest_type', sa.String(length=64), nullable=True),
        sa.Column('component_count', sa.Integer(), nullable=False),
        sa.Column('quality_score', sa.Float(), nullable=False),
        sa.Column('sbom_data', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_sboms_name', 'sboms', ['name'])
    op.create_index('ix_sboms_created_at', 'sboms', ['created_at'])
    op.create_index('ix_sboms_project_id', 'sboms', ['project_id'])
    op.create_index('ix_sboms_manifest_type', 'sboms', ['manifest_type'])
    op.create_index('ix_sboms_project_created', 'sboms', ['project_id', 'created_at'])
    op.create_index('ix_sboms_name_version', 'sboms', ['name', 'version'])

    # 3. Components
    op.create_table(
        'components',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('sbom_id', sa.String(length=64), nullable=False),
        sa.Column('project_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=128), nullable=False),
        sa.Column('type', sa.String(length=64), nullable=False),
        sa.Column('purl', sa.String(length=512), nullable=True),
        sa.Column('ecosystem', sa.String(length=64), nullable=True),
        sa.Column('license', sa.String(length=255), nullable=True),
        sa.Column('is_direct', sa.Boolean(), nullable=False),
        sa.Column('depth', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['sbom_id'], ['sboms.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_components_sbom_id', 'components', ['sbom_id'])
    op.create_index('ix_components_project_id', 'components', ['project_id'])
    op.create_index('ix_components_name', 'components', ['name'])
    op.create_index('ix_components_version', 'components', ['version'])
    op.create_index('ix_components_purl', 'components', ['purl'])
    op.create_index('ix_components_ecosystem', 'components', ['ecosystem'])
    op.create_index('ix_components_name_version', 'components', ['name', 'version'])
    op.create_index('ix_components_sbom_purl', 'components', ['sbom_id', 'purl'])
    op.create_index('ix_components_ecosystem_name', 'components', ['ecosystem', 'name'])

    # 4. Scans
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('project_id', sa.String(length=64), nullable=False),
        sa.Column('sbom_id', sa.String(length=64), nullable=False),
        sa.Column('sbom_name', sa.String(length=255), nullable=True),
        sa.Column('total_components', sa.Integer(), nullable=False),
        sa.Column('components_scanned', sa.Integer(), nullable=False),
        sa.Column('total_vulnerabilities', sa.Integer(), nullable=False),
        sa.Column('critical_count', sa.Integer(), nullable=False),
        sa.Column('high_count', sa.Integer(), nullable=False),
        sa.Column('medium_count', sa.Integer(), nullable=False),
        sa.Column('low_count', sa.Integer(), nullable=False),
        sa.Column('overall_risk_level', sa.String(length=32), nullable=False),
        sa.Column('overall_risk_score', sa.Float(), nullable=False),
        sa.Column('scan_data', sa.JSON(), nullable=False),
        sa.Column('scanned_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['sbom_id'], ['sboms.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scans_project_id', 'scans', ['project_id'])
    op.create_index('ix_scans_sbom_id', 'scans', ['sbom_id'])
    op.create_index('ix_scans_overall_risk_level', 'scans', ['overall_risk_level'])
    op.create_index('ix_scans_scanned_at', 'scans', ['scanned_at'])
    op.create_index('ix_scans_project_scanned_at', 'scans', ['project_id', 'scanned_at'])
    op.create_index('ix_scans_risk_level_score', 'scans', ['overall_risk_level', 'overall_risk_score'])

    # 5. Vulnerabilities
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('project_id', sa.String(length=64), nullable=False),
        sa.Column('vuln_id', sa.String(length=64), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=True),
        sa.Column('title', sa.String(length=512), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=False),
        sa.Column('epss_score', sa.Float(), nullable=False),
        sa.Column('affected_component', sa.String(length=255), nullable=True),
        sa.Column('fixed_version', sa.String(length=128), nullable=True),
        sa.Column('exploit_available', sa.Boolean(), nullable=False),
        sa.Column('in_kev', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_vulnerabilities_scan_id', 'vulnerabilities', ['scan_id'])
    op.create_index('ix_vulnerabilities_project_id', 'vulnerabilities', ['project_id'])
    op.create_index('ix_vulnerabilities_vuln_id', 'vulnerabilities', ['vuln_id'])
    op.create_index('ix_vulnerabilities_severity', 'vulnerabilities', ['severity'])
    op.create_index('ix_vulnerabilities_cvss_score', 'vulnerabilities', ['cvss_score'])
    op.create_index('ix_vulnerabilities_epss_score', 'vulnerabilities', ['epss_score'])
    op.create_index('ix_vulnerabilities_affected_component', 'vulnerabilities', ['affected_component'])
    op.create_index('ix_vulnerabilities_in_kev', 'vulnerabilities', ['in_kev'])
    op.create_index('ix_vulns_scan_sev', 'vulnerabilities', ['scan_id', 'severity'])
    op.create_index('ix_vulns_cve_severity', 'vulnerabilities', ['vuln_id', 'severity'])
    op.create_index('ix_vulns_component_cve', 'vulnerabilities', ['affected_component', 'vuln_id'])


def downgrade() -> None:
    op.drop_table('vulnerabilities')
    op.drop_table('scans')
    op.drop_table('components')
    op.drop_table('sboms')
    op.drop_table('projects')
