"""
The differentiating piece of ModelGuard, same role as RiskWeave's
toxic_combinations.py plays there.

A pickle opcode scanner alone (picklescan, fickling, ModelScan) tells you
one isolated fact: "this file references os.system." That fact alone
doesn't tell you whether to block a deploy -- plenty of legitimate,
well-known models get flagged by naive scanners for indirect references
that never execute. What actually matters is the correlation: does this
model contain a genuine code-execution primitive, AND is its provenance
unverified, AND does the pipeline that will deserialize it have exploitable
weaknesses of its own. That three-way correlation -- not the opcode scan in
isolation -- is what ModelGuard scores and reports.

Usage:
    python aibom_risk.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ingestion.db import get_connection

# Same vocabulary and base weights as RiskWeave's SEVERITY_BASE, on purpose --
# a critical finding means the same thing across both of this author's tools.
SEVERITY_BASE = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "unknown": 1.5}

MODEL_QUERY = """
SELECT m.id AS model_id, m.model_ref, m.source
FROM models m
"""

WORST_PICKLE_FINDING_QUERY = """
SELECT pf.id, pf.opcode, pf.module_name, pf.qualified_name, pf.risk_category, pf.severity
FROM pickle_findings pf
JOIN model_files mf ON pf.model_file_id = mf.id
WHERE mf.model_id = %s
ORDER BY
    CASE pf.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC
LIMIT 1
"""

PROVENANCE_QUERY = """
SELECT publisher, publisher_verified, gated, has_model_card,
       trust_registry_match, known_bad_hash_match
FROM provenance_checks
WHERE model_id = %s
ORDER BY checked_at DESC
LIMIT 1
"""

WORST_PIPELINE_CVE_QUERY = """
SELECT pv.cve_id, pv.severity, pd.package_name, pd.version
FROM pipeline_vulnerabilities pv
JOIN pipeline_dependencies pd ON pv.dependency_id = pd.id
WHERE pv.severity IN ('critical', 'high')
ORDER BY CASE pv.severity WHEN 'critical' THEN 2 WHEN 'high' THEN 1 ELSE 0 END DESC
LIMIT 1
"""
# Note: pipeline vulnerabilities are scoped by pipeline_ref, not by model --
# a model doesn't "belong" to one pipeline. For the MVP we correlate against
# whatever pipeline scan is most recent; see README roadmap for scoping this
# per-deployment once a model->pipeline mapping table exists.


def score_model(pickle_finding, provenance, pipeline_cve) -> tuple[float, str, str, str]:
    """Return (score, reasoning, owasp_llm_category, mitre_atlas_technique)."""
    reasons = []
    score = 0.0
    owasp_category = "LLM03:2025 Supply Chain"
    mitre_technique = "AML.T0010 (AI Supply Chain Compromise)"

    if provenance and provenance.get("known_bad_hash_match"):
        # A known-bad hash is a slam dunk -- don't average it against
        # anything else, just flag it at max severity.
        return (10.0,
                "File hash matches a known-malicious artifact in the trust registry.",
                owasp_category, "AML.T0010.003 (AI Supply Chain Compromise: Model)")

    if pickle_finding:
        score += SEVERITY_BASE.get(pickle_finding["severity"], 2.0)
        reasons.append(
            f"model file references {pickle_finding['module_name']}.{pickle_finding['qualified_name']} "
            f"via {pickle_finding['opcode']} ({pickle_finding['risk_category']}, "
            f"{pickle_finding['severity']})"
        )
        if pickle_finding["risk_category"] == "code_execution":
            score += 2.5
            mitre_technique = "AML.T0010.003 (AI Supply Chain Compromise: Model)"
        elif pickle_finding["risk_category"] == "network_egress":
            score += 1.5
            reasons.append("finding includes network-capable calls (possible exfil/C2 channel)")

    if provenance:
        if not provenance.get("publisher_verified") and not provenance.get("trust_registry_match"):
            score += 3.5
            reasons.append(f"publisher '{provenance.get('publisher') or 'unknown'}' is unverified "
                            f"and not on the trust registry")
        if not provenance.get("has_model_card"):
            score += 1.0
            reasons.append("repo has no model card (no documented lineage/training data/license)")
    else:
        # No provenance check has been run at all -- treat as unknown-risk,
        # not zero-risk. This is a smaller bump than a confirmed-unverified
        # publisher because "not yet checked" and "checked and untrusted"
        # are different findings and shouldn't score the same.
        score += 1.5
        reasons.append("no provenance check has been run for this model yet")

    if pipeline_cve:
        bump = 2.0 if pipeline_cve["severity"] == "critical" else 1.5
        score += bump
        reasons.append(f"loading pipeline has {pipeline_cve['severity']} {pipeline_cve['cve_id']} "
                        f"in {pipeline_cve['package_name']}=={pipeline_cve['version']}")

    if not reasons:
        reasons.append("no pickle findings, verified/registered provenance, no correlated pipeline CVEs")

    score = min(score, 10.0)
    return score, "; ".join(reasons), owasp_category, mitre_technique


def run_correlation(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT id, model_ref FROM models")
        models = cur.fetchall()

        written = 0
        for model in models:
            cur.execute(WORST_PICKLE_FINDING_QUERY, (model["id"],))
            pickle_finding = cur.fetchone()

            cur.execute(PROVENANCE_QUERY, (model["id"],))
            provenance = cur.fetchone()

            cur.execute(WORST_PIPELINE_CVE_QUERY)
            pipeline_cve = cur.fetchone()

            score, reasoning, owasp_category, mitre_technique = score_model(
                pickle_finding, provenance, pipeline_cve
            )

            cur.execute(
                """
                INSERT INTO aibom_findings
                    (model_id, worst_pickle_finding_id, risk_score, reasoning,
                     owasp_llm_category, mitre_atlas_technique)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (model_id) DO UPDATE
                SET worst_pickle_finding_id = EXCLUDED.worst_pickle_finding_id,
                    risk_score = EXCLUDED.risk_score,
                    reasoning = EXCLUDED.reasoning,
                    owasp_llm_category = EXCLUDED.owasp_llm_category,
                    mitre_atlas_technique = EXCLUDED.mitre_atlas_technique,
                    detected_at = now(),
                    resolved = FALSE
                """,
                (model["id"], pickle_finding["id"] if pickle_finding else None,
                 score, reasoning, owasp_category, mitre_technique),
            )
            written += 1
    conn.commit()
    return written


def top_findings(conn, limit: int = 10):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT af.risk_score, af.reasoning, af.owasp_llm_category, af.mitre_atlas_technique,
                   m.model_ref
            FROM aibom_findings af
            JOIN models m ON m.id = af.model_id
            WHERE af.resolved = FALSE
            ORDER BY af.risk_score DESC
            LIMIT %s
            """,
            (limit,),
        )
        return cur.fetchall()


def main():
    conn = get_connection()
    try:
        n = run_correlation(conn)
        print(f"Scored {n} models.\n")
        print("Top risks:")
        for row in top_findings(conn):
            print(f"  [{row['risk_score']:.1f}] {row['model_ref']} -> {row['mitre_atlas_technique']}\n"
                  f"      {row['reasoning']}")
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
