#!/usr/bin/env python3
"""
CI/CD pre-deployment gate -- the ModelGuard equivalent of RiskWeave's Kyverno
admission-control policy. There's no Kubernetes admission controller for "a
model file about to be loaded," so the enforcement point here is a CI job:
scan the model, correlate, and fail the build if any model's risk score
crosses the configured threshold. Wire this into the same pipeline stage
that currently runs your SAST gate (SonarQube/Nexus IQ), not a separate one
-- it's the same "block on merge, don't just alert" pattern.

Exit codes: 0 = pass, 1 = blocked (score >= threshold), 2 = usage/config error.

Usage:
    python ci/gate.py --model-ref org/model-name --threshold 7.0
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ingestion.db import get_connection


def main():
    parser = argparse.ArgumentParser(description="Fail the build if a scanned model exceeds the risk threshold")
    parser.add_argument("--model-ref", required=True)
    parser.add_argument("--threshold", type=float, default=7.0,
                         help="Block if risk_score >= this value (default 7.0, same 'genuinely dangerous' "
                              "cutoff RiskWeave's narrate step uses)")
    args = parser.parse_args()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT af.risk_score, af.reasoning, af.mitre_atlas_technique
                FROM aibom_findings af
                JOIN models m ON m.id = af.model_id
                WHERE m.model_ref = %s
                """,
                (args.model_ref,),
            )
            row = cur.fetchone()
    finally:
        conn.close()

    if row is None:
        print(f"::error::No ModelGuard findings for '{args.model_ref}'. "
              f"Run scan-model + check-provenance + correlate before the gate.", file=sys.stderr)
        sys.exit(2)

    score = row["risk_score"]
    if score >= args.threshold:
        print(f"::error::BLOCKED -- {args.model_ref} scored {score:.1f} "
              f"(threshold {args.threshold}): {row['reasoning']}")
        print(f"::error::MITRE ATLAS: {row['mitre_atlas_technique']}")
        sys.exit(1)

    print(f"PASS -- {args.model_ref} scored {score:.1f} (threshold {args.threshold})")
    sys.exit(0)


if __name__ == "__main__":
    main()
