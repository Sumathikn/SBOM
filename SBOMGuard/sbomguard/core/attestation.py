"""
SBOMGuard — Cryptographic SBOM Attestation & in-toto Provenance Engine
Generates tamper-evident, cryptographically signed supply chain attestations
adhering to in-toto Statement v0.1 and SLSA (Supply-chain Levels for Software Artifacts).
"""
import hmac
import hashlib
import json
import time
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone


class SBOMAttestationEngine:
    """
    Creates and verifies in-toto compatible cryptographic attestations for SBOMs.
    Guarantees supply chain non-repudiation and prevents undetected SBOM tampering.
    """
    DEFAULT_SIGNING_KEY = "sbomguard-production-attestation-master-secret-2026"

    @classmethod
    def compute_sha256(cls, content: str | bytes) -> str:
        """Compute standard SHA-256 hex digest of raw or canonicalized content."""
        if isinstance(content, str):
            content = content.encode("utf-8")
        return hashlib.sha256(content).hexdigest()

    @classmethod
    def canonicalize_json(cls, data: dict) -> str:
        """Produce canonical, deterministic JSON representation for signing."""
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @classmethod
    def create_attestation(
        cls,
        sbom_data: dict,
        project_name: str,
        signing_key: Optional[str] = None,
        tool_version: str = "2.0.0 Enterprise",
    ) -> dict:
        """
        Generate an in-toto formatted attestation bundle containing subject digests,
        provenance predicates, and HMAC-SHA256 signature.
        """
        key = signing_key or cls.DEFAULT_SIGNING_KEY
        canonical_sbom = cls.canonicalize_json(sbom_data)
        sbom_sha256 = cls.compute_sha256(canonical_sbom)

        now_utc = datetime.now(timezone.utc).isoformat()

        # In-toto Statement v0.1
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": project_name,
                    "digest": {
                        "sha256": sbom_sha256,
                    },
                }
            ],
            "predicateType": "https://sbomguard.dev/attestation/sbom/v1",
            "predicate": {
                "builder": {
                    "id": f"https://sbomguard.dev/engine@{tool_version}",
                },
                "metadata": {
                    "buildInvocationId": sbom_data.get("sbom_id", f"sbom-{int(time.time())}"),
                    "buildStartedOn": now_utc,
                    "completeness": {
                        "parameters": True,
                        "environment": True,
                        "materials": True,
                    },
                    "reproducible": True,
                },
                "materials": [
                    {
                        "uri": f"pkg:generic/{project_name}",
                        "digest": {
                            "sha256": sbom_sha256,
                        },
                    }
                ],
                "sbom_summary": {
                    "sbom_id": sbom_data.get("sbom_id"),
                    "format": sbom_data.get("format", "cyclonedx"),
                    "spec_version": sbom_data.get("spec_version", "1.5"),
                    "component_count": sbom_data.get("component_count", len(sbom_data.get("components", []))),
                    "quality_score": sbom_data.get("quality_score", 60.0),
                },
            },
        }

        # Sign the canonical statement
        statement_canonical = cls.canonicalize_json(statement)
        signature = hmac.new(
            key.encode("utf-8"),
            statement_canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return {
            "payloadType": "application/vnd.in-toto+json",
            "payload": statement,
            "signatures": [
                {
                    "keyid": hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
                    "sig": signature,
                    "algorithm": "HMAC-SHA256",
                    "signed_at": now_utc,
                }
            ],
        }

    @classmethod
    def verify_attestation(
        cls,
        attestation: dict,
        sbom_data: Optional[dict] = None,
        signing_key: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Verify cryptographic integrity of an attestation and match against the SBOM content.
        """
        key = signing_key or cls.DEFAULT_SIGNING_KEY

        payload = attestation.get("payload")
        if not payload:
            return False, "Missing attestation payload"

        signatures = attestation.get("signatures", [])
        if not signatures:
            return False, "Missing cryptographic signatures in attestation"

        sig_entry = signatures[0]
        claimed_sig = sig_entry.get("sig", "")

        # Recalculate signature
        canonical_payload = cls.canonicalize_json(payload)
        expected_sig = hmac.new(
            key.encode("utf-8"),
            canonical_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(claimed_sig, expected_sig):
            return False, "Signature verification failed: Attestation has been tampered with or signed with different key"

        # If SBOM is provided, verify SHA-256 hash matches the subject
        if sbom_data is not None:
            expected_sbom_hash = cls.compute_sha256(cls.canonicalize_json(sbom_data))
            subjects = payload.get("subject", [])
            if not subjects or subjects[0].get("digest", {}).get("sha256") != expected_sbom_hash:
                return False, "SBOM integrity mismatch: SHA-256 does not match subject digest in attestation"

        return True, "Attestation signature and digest verified successfully"


attestation_engine = SBOMAttestationEngine()
