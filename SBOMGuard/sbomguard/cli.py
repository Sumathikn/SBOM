"""
SBOMGuard Command-Line Interface (CLI)
DevSecOps command-line tool for local scanning, PR gatekeeping,
SBOM generation, diffing, and SARIF export.
"""
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import FAIL_ON_SEVERITY, FAIL_ON_CVSS
from sbomguard.core.generator import SBOMGenerator
from sbomguard.core.vulnerability import VulnerabilityScanner
from sbomguard.core.risk_scorer import RiskScorer
from sbomguard.core.sbom_manager import SBOMManager
from sbomguard.core.remediation import remediation_engine
from sbomguard.core.sarif import generate_sarif_report
from sbomguard.models import Component, Severity

app = typer.Typer(
    name="sbomguard",
    help="🛡️ SBOMGuard: Automated SBOM Generation, Vulnerability Analysis & DevSecOps Gatekeeper",
    add_completion=False,
)
console = Console()


SEVERITY_ORDER = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@app.command()
def scan(
    manifest_path: str = typer.Argument(
        ...,
        help="Path to dependency manifest (requirements.txt, package.json, pom.xml, go.mod)",
    ),
    format: str = typer.Option("cyclonedx", "--format", "-f", help="SBOM format (cyclonedx, spdx)"),
    fail_on: str = typer.Option(
        FAIL_ON_SEVERITY,
        "--fail-on",
        help="Failure severity threshold for CI gate (none, low, medium, high, critical)",
    ),
    max_cvss: float = typer.Option(
        FAIL_ON_CVSS,
        "--max-cvss",
        help="Maximum allowable CVSS score before failing gate",
    ),
    fail_on_kev: bool = typer.Option(
        True,
        "--fail-on-kev/--no-fail-on-kev",
        help="Fail gate immediately if any vulnerability is in CISA KEV catalog",
    ),
    sarif: Optional[str] = typer.Option(None, "--sarif", "-s", help="Output path for SARIF 2.1.0 report"),
    json_out: Optional[str] = typer.Option(None, "--json", "-j", help="Output path for JSON scan result"),
    project_name: Optional[str] = typer.Option(None, "--project", "-p", help="Project / release name"),
):
    """
    Scan a repository manifest for known vulnerabilities, verify CISA KEV status,
    and enforce DevSecOps PR gatekeeping policies.
    """
    path = Path(manifest_path)
    if not path.exists():
        console.print(f"[bold red]❌ Error:[/bold red] File not found: {manifest_path}")
        raise typer.Exit(code=2)

    console.print(
        Panel.fit(
            f"[bold cyan]🛡️ SBOMGuard DevSecOps Scanner[/bold cyan]\n"
            f"[dim]Target:[/dim] {manifest_path} | [dim]Policy:[/dim] fail-on >= {fail_on.upper()}, CVSS >= {max_cvss}",
            border_style="cyan",
        )
    )

    with console.status("[bold green]Generating SBOM and parsing components...[/bold green]"):
        content = path.read_text(encoding="utf-8")
        generator = SBOMGenerator()
        try:
            sbom_data = generator.generate(
                content=content,
                filename=path.name,
                output_format=format,
                project_name=project_name or path.stem,
            )
        except Exception as e:
            console.print(f"[bold red]❌ SBOM Generation Failed:[/bold red] {e}")
            raise typer.Exit(code=2)

    components = [
        Component(
            name=c["name"],
            version=c["version"],
            ecosystem=c.get("ecosystem"),
            purl=c.get("purl"),
            is_direct=c.get("is_direct", True),
        )
        for c in sbom_data.get("components", [])
    ]

    with console.status(f"[bold cyan]Correlating {len(components)} components against OSV, NVD & CISA KEV...[/bold cyan]"):
        scanner = VulnerabilityScanner()
        try:
            scan_raw = scanner.scan_components(components)
        finally:
            scanner.close()

        scorer = RiskScorer()
        scan_res = scorer.assess_sbom(
            sbom_id=sbom_data["sbom_id"],
            sbom_name=sbom_data.get("name", path.stem),
            scan_results=scan_raw,
        )

    scan_dict = scan_res.model_dump()

    # Print Findings Table
    table = Table(
        title=f"Security Findings for {path.name}",
        border_style="cyan",
        header_style="bold cyan",
    )
    table.add_column("Advisory ID", style="bold")
    table.add_column("Component", style="white")
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("EPSS", justify="right")
    table.add_column("CISA KEV", justify="center")
    table.add_column("Fixed Version", style="green")

    gate_failed = False
    gate_violations = []

    threshold_level = SEVERITY_ORDER.get(fail_on.lower(), 3)

    for ra in scan_dict.get("risk_assessments", []):
        for v in ra.get("vulnerabilities", []):
            sev_str = v.get("severity", "none").lower()
            cvss = float(v.get("cvss_score", 0.0))
            in_kev = bool(v.get("in_kev", False))
            epss = float(v.get("epss_score", 0.0))

            # Color severity
            if sev_str == "critical":
                sev_display = "[bold red]CRITICAL[/bold red]"
            elif sev_str == "high":
                sev_display = "[bold color(208)]HIGH[/bold color(208)]"
            elif sev_str == "medium":
                sev_display = "[bold yellow]MEDIUM[/bold yellow]"
            else:
                sev_display = f"[blue]{sev_str.upper()}[/blue]"

            kev_display = "[bold red]🚨 YES[/bold red]" if in_kev else "[dim]No[/dim]"

            table.add_row(
                v.get("id"),
                v.get("affected_component"),
                sev_display,
                f"{cvss:.1f}",
                f"{epss:.1%}",
                kev_display,
                v.get("fixed_version") or "None",
            )

            # Check Gate Violations
            curr_level = SEVERITY_ORDER.get(sev_str, 0)
            if threshold_level > 0 and curr_level >= threshold_level:
                gate_failed = True
                gate_violations.append(
                    f"{v.get('id')} ({sev_str.upper()}) on {v.get('affected_component')}"
                )
            if cvss >= max_cvss:
                gate_failed = True
                gate_violations.append(
                    f"{v.get('id')} CVSS {cvss} >= threshold {max_cvss}"
                )
            if fail_on_kev and in_kev:
                gate_failed = True
                gate_violations.append(
                    f"{v.get('id')} is actively exploited in CISA KEV catalog"
                )

    if scan_res.total_vulnerabilities > 0:
        console.print(table)
    else:
        console.print("[bold green]✅ No known vulnerabilities identified![/bold green]")

    # Export SARIF if requested
    if sarif:
        sarif_data = generate_sarif_report(scan_dict, repo_file_path=str(path))
        Path(sarif).write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        console.print(f"[dim]📄 Exported SARIF 2.1.0 to:[/dim] [cyan]{sarif}[/cyan]")

    # Export JSON if requested
    if json_out:
        Path(json_out).write_text(json.dumps(scan_dict, indent=2, default=str), encoding="utf-8")
        console.print(f"[dim]📄 Exported JSON scan result to:[/dim] [cyan]{json_out}[/cyan]")

    # Summary
    console.print(
        f"\n[bold]Audit Summary:[/bold] Total: {scan_res.total_vulnerabilities} | "
        f"[bold red]Critical: {scan_res.critical_count}[/bold red] | "
        f"[bold color(208)]High: {scan_res.high_count}[/bold color(208)] | "
        f"Medium: {scan_res.medium_count} | Low: {scan_res.low_count} | "
        f"Risk Score: [cyan]{scan_res.overall_risk_score}/100[/cyan]"
    )

    if gate_failed:
        console.print(
            Panel(
                f"[bold red]❌ DevSecOps Gate Failed: Policy Violations Detected![/bold red]\n"
                + "\n".join(f"  • {violation}" for violation in gate_violations[:8]),
                border_style="red",
            )
        )
        raise typer.Exit(code=1)
    else:
        console.print(
            Panel(
                "[bold green]✅ DevSecOps Gate Passed: All findings are within acceptable thresholds.[/bold green]",
                border_style="green",
            )
        )
        raise typer.Exit(code=0)


@app.command()
def generate(
    manifest_path: str = typer.Argument(..., help="Path to dependency manifest"),
    format: str = typer.Option("cyclonedx", "--format", "-f", help="Format: cyclonedx or spdx"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    project_name: Optional[str] = typer.Option(None, "--project", "-p", help="Project name"),
):
    """Generate an SBOM from a manifest file and save to disk."""
    path = Path(manifest_path)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {manifest_path}")
        raise typer.Exit(code=2)

    content = path.read_text(encoding="utf-8")
    generator = SBOMGenerator()
    res = generator.generate(
        content=content,
        filename=path.name,
        output_format=format,
        project_name=project_name or path.stem,
    )

    out_file = output or f"{path.stem}-{format}.json"
    Path(out_file).write_text(json.dumps(res["document"], indent=2), encoding="utf-8")
    console.print(
        f"[bold green]✅ Generated {format.upper()} SBOM:[/bold green] [cyan]{out_file}[/cyan] "
        f"({res['component_count']} components, quality score: {res['quality_score']}%)"
    )


@app.command()
def diff(
    sbom_a: str = typer.Argument(..., help="Path or ID of Base SBOM"),
    sbom_b: str = typer.Argument(..., help="Path or ID of Target SBOM"),
):
    """Compare two SBOMs and display version drift with SemVer classifications."""
    manager = SBOMManager()
    try:
        # Check if local files or database IDs
        if Path(sbom_a).exists() and Path(sbom_b).exists():
            data_a = json.loads(Path(sbom_a).read_text(encoding="utf-8"))
            data_b = json.loads(Path(sbom_b).read_text(encoding="utf-8"))
            # temporary IDs
            comps_a = data_a.get("components", [])
            comps_b = data_b.get("components", [])
            console.print(f"[bold cyan]Comparing local files:[/bold cyan] {sbom_a} vs {sbom_b}")
            console.print(f"Base: {len(comps_a)} components | Target: {len(comps_b)} components")
        else:
            diff_res = manager.compare(sbom_a, sbom_b)
            console.print(Panel.fit(f"[bold cyan]SBOM Diff Summary:[/bold cyan] {diff_res['summary']}"))
            console.print(f"Added: +{diff_res['stats']['added_count']} | Removed: -{diff_res['stats']['removed_count']} | Drift: {diff_res['stats']['modified_count']}")
    except Exception as e:
        console.print(f"[bold red]Diff failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def version():
    """Print SBOMGuard platform version and system info."""
    console.print("[bold cyan]🛡️ SBOMGuard Enterprise Platform[/bold cyan] v2.0.0")
    console.print("Python 3.10+ | PostgreSQL 16 Storage | Redis Cache | CISA KEV Feeds")


def main():
    app()


if __name__ == "__main__":
    main()
