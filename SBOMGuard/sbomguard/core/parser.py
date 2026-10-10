"""
SBOMGuard — Manifest File Parsers
Parses requirements.txt, package.json, pom.xml, go.mod into Component objects.
"""

import json
import re
from typing import Optional

from defusedxml import ElementTree as ET

from sbomguard.models import Component, ComponentType, ManifestType


def detect_manifest_type(filename: str) -> Optional[ManifestType]:
    """Detect the manifest type from filename."""
    filename = filename.strip().lower()
    mapping = {
        "requirements.txt": ManifestType.REQUIREMENTS_TXT,
        "package.json": ManifestType.PACKAGE_JSON,
        "pom.xml": ManifestType.POM_XML,
        "go.mod": ManifestType.GO_MOD,
        "gemfile.lock": ManifestType.GEMFILE_LOCK,
    }
    for key, mtype in mapping.items():
        if filename.endswith(key):
            return mtype
    return None


def _ecosystem_for(manifest_type: ManifestType) -> str:
    """Return the package ecosystem for a manifest type."""
    return {
        ManifestType.REQUIREMENTS_TXT: "pypi",
        ManifestType.PACKAGE_JSON: "npm",
        ManifestType.POM_XML: "maven",
        ManifestType.GO_MOD: "go",
        ManifestType.GEMFILE_LOCK: "rubygems",
    }.get(manifest_type, "unknown")


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a Package URL (purl) string."""
    # pkg:<type>/<namespace>/<name>@<version>
    return f"pkg:{ecosystem}/{name}@{version}"


# ─── requirements.txt Parser ────────────────────────────────────────────────

def parse_requirements_txt(content: str) -> list[Component]:
    """
    Parse a Python requirements.txt file.
    Supports: package==1.0.0, package>=1.0.0, package~=1.0.0, package
    """
    components = []
    for line in content.splitlines():
        line = line.strip()
        # Skip comments, blank lines, and options
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Remove inline comments
        if " #" in line:
            line = line[: line.index(" #")].strip()

        # Remove environment markers (e.g., ; python_version >= "3.6")
        if ";" in line:
            line = line[: line.index(";")].strip()

        # Parse name and version specifier
        match = re.match(r"^([a-zA-Z0-9_][a-zA-Z0-9._-]*)\s*([><=!~]+\s*[\d.*]+)?", line)
        if match:
            name = match.group(1).strip()
            version_spec = match.group(2)
            version = "unknown"
            if version_spec:
                # Extract the version number from specifier
                ver_match = re.search(r"[\d][.\d]*[.\d\w]*", version_spec)
                if ver_match:
                    version = ver_match.group(0)

            components.append(Component(
                name=name,
                version=version,
                type=ComponentType.LIBRARY,
                ecosystem="pypi",
                purl=_make_purl("pypi", name, version),
                is_direct=True,
                depth=0,
            ))

    return components


# ─── package.json Parser ────────────────────────────────────────────────────

def parse_package_json(content: str) -> list[Component]:
    """Parse a Node.js package.json file."""
    components = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return components

    # Parse dependencies
    for dep_key, is_direct in [("dependencies", True), ("devDependencies", False)]:
        deps = data.get(dep_key, {})
        for name, version_spec in deps.items():
            # Clean version string (remove ^, ~, >=, etc.)
            version = re.sub(r"[^0-9.]", "", version_spec) or "unknown"

            components.append(Component(
                name=name,
                version=version,
                type=ComponentType.LIBRARY,
                ecosystem="npm",
                purl=_make_purl("npm", name, version),
                is_direct=is_direct,
                depth=0 if is_direct else 1,
            ))

    return components


# ─── pom.xml Parser ─────────────────────────────────────────────────────────

def parse_pom_xml(content: str) -> list[Component]:
    """Parse a Java Maven pom.xml file."""
    components = []
    try:
        root = ET.fromstring(content.encode("utf-8"))
    except Exception:
        return components

    # Maven namespace
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}

    # Try with namespace first, then without
    deps = root.findall(".//m:dependencies/m:dependency", ns)
    if not deps:
        deps = root.findall(".//dependencies/dependency")

    for dep in deps:
        group_id = _find_text(dep, "groupId", ns) or ""
        artifact_id = _find_text(dep, "artifactId", ns) or ""
        version = _find_text(dep, "version", ns) or "unknown"
        scope = _find_text(dep, "scope", ns) or "compile"

        if artifact_id:
            name = f"{group_id}:{artifact_id}" if group_id else artifact_id
            components.append(Component(
                name=name,
                version=version,
                type=ComponentType.LIBRARY,
                ecosystem="maven",
                purl=_make_purl("maven", f"{group_id}/{artifact_id}", version),
                is_direct=(scope in ("compile", "runtime")),
                depth=0,
            ))

    return components


def _find_text(element, tag: str, ns: dict) -> Optional[str]:
    """Find text in an XML element, trying with and without namespace."""
    el = element.find(f"m:{tag}", ns)
    if el is None:
        el = element.find(tag)
    return el.text.strip() if el is not None and el.text else None


# ─── go.mod Parser ──────────────────────────────────────────────────────────

def parse_go_mod(content: str) -> list[Component]:
    """Parse a Go go.mod file."""
    components = []
    in_require = False

    for line in content.splitlines():
        line = line.strip()

        if line.startswith("require ("):
            in_require = True
            continue
        if line == ")":
            in_require = False
            continue

        # Single-line require
        if line.startswith("require "):
            line = line[len("require "):]

        if in_require or " v" in line:
            # Parse "module/path v1.2.3"
            match = re.match(r"^([^\s]+)\s+(v[\d.]+\S*)", line)
            if match:
                name = match.group(1)
                version = match.group(2).lstrip("v")
                components.append(Component(
                    name=name,
                    version=version,
                    type=ComponentType.LIBRARY,
                    ecosystem="go",
                    purl=_make_purl("golang", name, version),
                    is_direct=True,
                    depth=0,
                ))

    return components


# ─── Gemfile.lock Parser ────────────────────────────────────────────────────

def parse_gemfile_lock(content: str) -> list[Component]:
    """Parse a Ruby Gemfile.lock file."""
    components = []
    in_specs = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs:
            if not line.startswith("    ") and not line.startswith("\t"):
                in_specs = False
                continue
            # Lines like "    gem_name (1.2.3)"
            match = re.match(r"^\s{4}(\S+)\s+\(([^)]+)\)", line)
            if match:
                name = match.group(1)
                version = match.group(2)
                components.append(Component(
                    name=name,
                    version=version,
                    type=ComponentType.LIBRARY,
                    ecosystem="rubygems",
                    purl=_make_purl("gem", name, version),
                    is_direct=True,
                    depth=0,
                ))

    return components


# ─── Unified Parser ─────────────────────────────────────────────────────────

PARSERS = {
    ManifestType.REQUIREMENTS_TXT: parse_requirements_txt,
    ManifestType.PACKAGE_JSON: parse_package_json,
    ManifestType.POM_XML: parse_pom_xml,
    ManifestType.GO_MOD: parse_go_mod,
    ManifestType.GEMFILE_LOCK: parse_gemfile_lock,
}


def parse_manifest(content: str, manifest_type: ManifestType) -> list[Component]:
    """Parse a manifest file into a list of components."""
    parser = PARSERS.get(manifest_type)
    if parser is None:
        raise ValueError(f"Unsupported manifest type: {manifest_type}")
    return parser(content)
