import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from correlation.aibom_risk import score_model


def test_clean_model_scores_low():
    score, reasoning, owasp, mitre = score_model(
        pickle_finding=None,
        provenance={"publisher": "acme-ai", "publisher_verified": True, "gated": False,
                    "has_model_card": True, "trust_registry_match": True, "known_bad_hash_match": False},
        pipeline_cve=None,
    )
    assert score < 3.0


def test_code_execution_finding_plus_unverified_publisher_scores_high():
    score, reasoning, owasp, mitre = score_model(
        pickle_finding={"module_name": "os", "qualified_name": "system",
                        "opcode": "STACK_GLOBAL", "risk_category": "code_execution", "severity": "critical"},
        provenance={"publisher": "rando123", "publisher_verified": False, "gated": False,
                    "has_model_card": False, "trust_registry_match": False, "known_bad_hash_match": False},
        pipeline_cve=None,
    )
    assert score >= 8.0
    assert "os.system" in reasoning
    assert "unverified" in reasoning
    assert mitre == "AML.T0010.003 (AI Supply Chain Compromise: Model)"


def test_known_bad_hash_overrides_everything():
    score, reasoning, owasp, mitre = score_model(
        pickle_finding=None,
        provenance={"publisher": "acme-ai", "publisher_verified": True, "gated": False,
                    "has_model_card": True, "trust_registry_match": True, "known_bad_hash_match": True},
        pipeline_cve=None,
    )
    assert score == 10.0


def test_severity_floor_matches_riskweave_vocabulary():
    """Same critical/high/medium/low base weights as RiskWeave's
    toxic_combinations.SEVERITY_BASE -- a critical finding should mean the
    same thing in both of this author's tools."""
    from correlation.aibom_risk import SEVERITY_BASE
    assert SEVERITY_BASE["critical"] == 4.0
    assert SEVERITY_BASE["high"] == 3.0
    assert SEVERITY_BASE["medium"] == 2.0
    assert SEVERITY_BASE["low"] == 1.0


def test_pipeline_cve_adds_to_score_without_pickle_finding():
    score, reasoning, owasp, mitre = score_model(
        pickle_finding=None,
        provenance={"publisher": "acme-ai", "publisher_verified": True, "gated": False,
                    "has_model_card": True, "trust_registry_match": True, "known_bad_hash_match": False},
        pipeline_cve={"cve_id": "CVE-2024-99999", "severity": "critical",
                      "package_name": "torch", "version": "2.0.0"},
    )
    assert score >= 2.0
    assert "torch" in reasoning
