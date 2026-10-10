"""
SBOMGuard — Unit Tests for SBOM Generation & Parsing
Tests the manifest parsers and SBOM generator engine.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from sbomguard.core.parser import (
    detect_manifest_type,
    parse_requirements_txt,
    parse_package_json,
    parse_pom_xml,
    parse_go_mod,
    parse_manifest,
)
from sbomguard.models import ManifestType


# ─── Manifest Detection ─────────────────────────────────────────

class TestManifestDetection:
    def test_detect_requirements_txt(self):
        assert detect_manifest_type("requirements.txt") == ManifestType.REQUIREMENTS_TXT

    def test_detect_package_json(self):
        assert detect_manifest_type("package.json") == ManifestType.PACKAGE_JSON

    def test_detect_pom_xml(self):
        assert detect_manifest_type("pom.xml") == ManifestType.POM_XML

    def test_detect_go_mod(self):
        assert detect_manifest_type("go.mod") == ManifestType.GO_MOD

    def test_detect_gemfile_lock(self):
        assert detect_manifest_type("Gemfile.lock") == ManifestType.GEMFILE_LOCK

    def test_detect_unknown(self):
        assert detect_manifest_type("Dockerfile") is None

    def test_detect_path(self):
        assert detect_manifest_type("/project/src/requirements.txt") == ManifestType.REQUIREMENTS_TXT


# ─── requirements.txt Parser ────────────────────────────────────

class TestRequirementsParser:
    def test_basic_pinned(self):
        content = "flask==2.3.0\nrequests==2.31.0"
        comps = parse_requirements_txt(content)
        assert len(comps) == 2
        assert comps[0].name == "flask"
        assert comps[0].version == "2.3.0"
        assert comps[0].ecosystem == "pypi"

    def test_version_specifiers(self):
        content = "django>=4.2\nnumpy~=1.25.0\nscipy"
        comps = parse_requirements_txt(content)
        assert len(comps) == 3
        assert comps[0].name == "django"
        assert comps[0].version == "4.2"
        assert comps[2].name == "scipy"
        assert comps[2].version == "unknown"

    def test_skip_comments_and_blanks(self):
        content = "# This is a comment\nflask==2.3.0\n\n# Another comment\n-r base.txt"
        comps = parse_requirements_txt(content)
        assert len(comps) == 1
        assert comps[0].name == "flask"

    def test_inline_comments(self):
        content = "flask==2.3.0  # Web framework"
        comps = parse_requirements_txt(content)
        assert len(comps) == 1
        assert comps[0].name == "flask"

    def test_environment_markers(self):
        content = 'pywin32==306; sys_platform == "win32"'
        comps = parse_requirements_txt(content)
        assert len(comps) == 1
        assert comps[0].name == "pywin32"

    def test_purl_generation(self):
        content = "flask==2.3.0"
        comps = parse_requirements_txt(content)
        assert comps[0].purl == "pkg:pypi/flask@2.3.0"

    def test_empty_content(self):
        comps = parse_requirements_txt("")
        assert len(comps) == 0


# ─── package.json Parser ────────────────────────────────────────

class TestPackageJsonParser:
    def test_basic_dependencies(self):
        content = '{"dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"}}'
        comps = parse_package_json(content)
        assert len(comps) == 2
        assert comps[0].name == "express"
        assert comps[0].ecosystem == "npm"
        assert comps[0].is_direct is True

    def test_dev_dependencies(self):
        content = '{"devDependencies": {"jest": "^29.7.0"}}'
        comps = parse_package_json(content)
        assert len(comps) == 1
        assert comps[0].is_direct is False

    def test_mixed_dependencies(self):
        content = '{"dependencies": {"express": "^4.18.2"}, "devDependencies": {"jest": "^29.7.0"}}'
        comps = parse_package_json(content)
        assert len(comps) == 2

    def test_invalid_json(self):
        comps = parse_package_json("not json")
        assert len(comps) == 0

    def test_no_dependencies(self):
        content = '{"name": "test", "version": "1.0.0"}'
        comps = parse_package_json(content)
        assert len(comps) == 0


# ─── pom.xml Parser ─────────────────────────────────────────────

class TestPomXmlParser:
    def test_basic_maven(self):
        content = """<?xml version="1.0"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0">
            <dependencies>
                <dependency>
                    <groupId>org.springframework</groupId>
                    <artifactId>spring-core</artifactId>
                    <version>6.1.8</version>
                </dependency>
            </dependencies>
        </project>"""
        comps = parse_pom_xml(content)
        assert len(comps) == 1
        assert comps[0].name == "org.springframework:spring-core"
        assert comps[0].version == "6.1.8"
        assert comps[0].ecosystem == "maven"

    def test_test_scope(self):
        content = """<?xml version="1.0"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0">
            <dependencies>
                <dependency>
                    <groupId>junit</groupId>
                    <artifactId>junit</artifactId>
                    <version>4.13.2</version>
                    <scope>test</scope>
                </dependency>
            </dependencies>
        </project>"""
        comps = parse_pom_xml(content)
        assert len(comps) == 1
        assert comps[0].is_direct is False


# ─── go.mod Parser ──────────────────────────────────────────────

class TestGoModParser:
    def test_basic_go_mod(self):
        content = """module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/go-sql-driver/mysql v1.8.1
)"""
        comps = parse_go_mod(content)
        assert len(comps) == 2
        assert comps[0].name == "github.com/gin-gonic/gin"
        assert comps[0].version == "1.9.1"
        assert comps[0].ecosystem == "go"


# ─── Unified Parser ─────────────────────────────────────────────

class TestUnifiedParser:
    def test_parse_manifest_requirements(self):
        comps = parse_manifest("flask==2.3.0", ManifestType.REQUIREMENTS_TXT)
        assert len(comps) == 1

    def test_parse_manifest_unsupported(self):
        with pytest.raises(ValueError):
            parse_manifest("content", "unsupported_type")


# ─── Integration: Sample Files ──────────────────────────────────

class TestSampleFiles:
    SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data" / "sample"

    def test_parse_sample_requirements(self):
        filepath = self.SAMPLE_DIR / "requirements.txt"
        if filepath.exists():
            content = filepath.read_text()
            comps = parse_requirements_txt(content)
            assert len(comps) >= 15  # Our sample has 20 packages
            names = [c.name for c in comps]
            assert "flask" in names
            assert "requests" in names

    def test_parse_sample_package_json(self):
        filepath = self.SAMPLE_DIR / "package.json"
        if filepath.exists():
            content = filepath.read_text()
            comps = parse_package_json(content)
            assert len(comps) >= 10
            names = [c.name for c in comps]
            assert "express" in names

    def test_parse_sample_pom_xml(self):
        filepath = self.SAMPLE_DIR / "pom.xml"
        if filepath.exists():
            content = filepath.read_text()
            comps = parse_pom_xml(content)
            assert len(comps) >= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
