"""
Property-Based Testing for Parsers and Diff Engine using Hypothesis
"""
import sys
from pathlib import Path
import pytest
from hypothesis import given, strategies as st, settings

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomguard.core.parser import parse_requirements_txt
from sbomguard.core.sbom_manager import SBOMManager


class TestPropertyBasedParsers:
    @given(
        pkg_name=st.from_regex(r"^[a-zA-Z][a-zA-Z0-9_-]{1,30}$", fullmatch=True),
        v_major=st.integers(min_value=0, max_value=99),
        v_minor=st.integers(min_value=0, max_value=99),
        v_patch=st.integers(min_value=0, max_value=99),
    )
    @settings(max_examples=50)
    def test_requirements_parser_version_invariants(self, pkg_name, v_major, v_minor, v_patch):
        ver_str = f"{v_major}.{v_minor}.{v_patch}"
        content = f"{pkg_name}=={ver_str}\n"

        comps = parse_requirements_txt(content)
        assert len(comps) == 1
        assert comps[0].name == pkg_name
        assert comps[0].version == ver_str
        assert comps[0].ecosystem == "pypi"
        assert f"pkg:pypi/{pkg_name}@{ver_str}" in comps[0].purl

    @given(
        maj_a=st.integers(min_value=0, max_value=50),
        min_a=st.integers(min_value=0, max_value=50),
        patch_a=st.integers(min_value=0, max_value=50),
        maj_b=st.integers(min_value=0, max_value=50),
        min_b=st.integers(min_value=0, max_value=50),
        patch_b=st.integers(min_value=0, max_value=50),
    )
    @settings(max_examples=50)
    def test_version_drift_classification_properties(
        self, maj_a, min_a, patch_a, maj_b, min_b, patch_b
    ):
        v_a = f"{maj_a}.{min_a}.{patch_a}"
        v_b = f"{maj_b}.{min_b}.{patch_b}"

        drift_type, breaking_risk = SBOMManager._classify_version_drift(v_a, v_b)

        if maj_a != maj_b:
            assert drift_type == "major"
            assert breaking_risk == "high"
        elif min_a != min_b:
            assert drift_type == "minor"
            assert breaking_risk == "medium"
        else:
            assert drift_type == "patch"
            assert breaking_risk == "low"
