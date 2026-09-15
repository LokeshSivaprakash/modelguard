"""
Parse a Syft SBOM for the ML pipeline environment that will *load* the model
(the inference service's requirements.txt / container image) -- the same
ingestion this author's RiskWeave project uses for application images,
retargeted at the ML pipeline instead. Deliberately reused rather than
reinvented: a vulnerable torch/transformers/numpy version in the loader is
part of the same attack surface as the model file itself, and scanning it
the same way keeps ModelGuard's findings comparable to RiskWeave's.

Generate the input with:
    syft dir:./inference-service -o syft-json > pipeline_sbom.json
    (or syft <image_ref> -o syft-json > pipeline_sbom.json for a containerized pipeline)

Usage:
    python parse_pipeline_sbom.py --pipeline-ref inference-service:latest --sbom-file pipeline_sbom.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ingestion.db import get_connection, record_scan


def load_pipeline_sbom(conn, pipeline_ref: str, sbom_path: str) -> int:
    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    artifacts = sbom.get("artifacts", [])
    count = 0
    with conn.cursor() as cur:
        for artifact in artifacts:
            name = artifact.get("name")
            version = artifact.get("version")
            ecosystem = artifact.get("type")
            if not name or not version:
                continue
            cur.execute(
                """
                INSERT INTO pipeline_dependencies (pipeline_ref, package_name, version, ecosystem)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (pipeline_ref, package_name, version) DO NOTHING
                """,
                (pipeline_ref, name, version, ecosystem),
            )
            count += 1
    conn.commit()
    return count


def main():
    parser = argparse.ArgumentParser(description="Load a Syft SBOM for an ML pipeline into ModelGuard")
    parser.add_argument("--pipeline-ref", required=True, help="e.g. inference-service:1.4.0")
    parser.add_argument("--sbom-file", required=True, help="Path to syft-json output")
    args = parser.parse_args()

    conn = get_connection()
    try:
        record_scan(conn, scan_type="pipeline_sbom", source_tool="syft",
                    target=args.pipeline_ref, raw_output_path=args.sbom_file)
        n = load_pipeline_sbom(conn, args.pipeline_ref, args.sbom_file)
        print(f"Loaded {n} pipeline dependencies for '{args.pipeline_ref}'")
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
