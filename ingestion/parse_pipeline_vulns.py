"""
Parse a Grype scan of the ML pipeline environment and load CVEs against
already-ingested pipeline dependencies. Run parse_pipeline_sbom.py first.

Generate the input with:
    grype dir:./inference-service -o json > pipeline_vulns.json

Usage:
    python parse_pipeline_vulns.py --pipeline-ref inference-service:latest --vuln-file pipeline_vulns.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ingestion.db import get_connection, record_scan


def get_dependency_id(conn, pipeline_ref: str, package_name: str, version: str):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM pipeline_dependencies WHERE pipeline_ref = %s AND package_name = %s AND version = %s",
            (pipeline_ref, package_name, version),
        )
        row = cur.fetchone()
        return row["id"] if row else None


def load_pipeline_vulns(conn, pipeline_ref: str, vuln_path: str):
    with open(vuln_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    matches = report.get("matches", [])
    loaded, skipped = 0, 0

    with conn.cursor() as cur:
        for match in matches:
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            package_name = artifact.get("name")
            version = artifact.get("version")
            cve_id = vuln.get("id")
            severity = (vuln.get("severity") or "unknown").lower()
            cvss_list = vuln.get("cvss", [])
            cvss_score = cvss_list[0].get("metrics", {}).get("baseScore") if cvss_list else None
            fixed_versions = vuln.get("fix", {}).get("versions", [])
            fixed_version = fixed_versions[0] if fixed_versions else None

            dependency_id = get_dependency_id(conn, pipeline_ref, package_name, version)
            if dependency_id is None:
                skipped += 1
                continue

            cur.execute(
                """
                INSERT INTO pipeline_vulnerabilities (dependency_id, cve_id, severity, cvss_score, fixed_version)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (dependency_id, cve_id) DO UPDATE
                SET severity = EXCLUDED.severity, cvss_score = EXCLUDED.cvss_score
                """,
                (dependency_id, cve_id, severity, cvss_score, fixed_version),
            )
            loaded += 1

    conn.commit()
    return loaded, skipped


def main():
    parser = argparse.ArgumentParser(description="Load a Grype vuln scan for an ML pipeline into ModelGuard")
    parser.add_argument("--pipeline-ref", required=True)
    parser.add_argument("--vuln-file", required=True)
    args = parser.parse_args()

    conn = get_connection()
    try:
        record_scan(conn, scan_type="pipeline_vuln", source_tool="grype",
                    target=args.pipeline_ref, raw_output_path=args.vuln_file)
        loaded, skipped = load_pipeline_vulns(conn, args.pipeline_ref, args.vuln_file)
        print(f"Loaded {loaded} pipeline vulnerabilities ({skipped} skipped, no matching dependency row)")
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
