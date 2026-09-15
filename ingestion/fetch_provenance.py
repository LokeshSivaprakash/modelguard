"""
Pull publisher/provenance signal for a model from the Hugging Face Hub API,
and cross-check it against a local trust registry.

This deliberately does NOT try to verify cryptographic signing -- as of this
writing there's no universal signed-model-card standard in wide use across
hubs, so claiming that would be exactly the kind of overclaim this project's
author has explicitly decided to avoid. What this checks instead is real and
useful: is the file hash on a known-bad list, is the publishing org one this
team has already vetted, does the repo have a model card at all, is it gated.
Those are legitimate, honestly-scoped provenance signals -- not a substitute
for supply-chain signing once that exists broadly.

Usage:
    python fetch_provenance.py --model-ref org/model-name
"""
import argparse
import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ingestion.db import get_connection, upsert_model, record_scan

HF_API_BASE = "https://huggingface.co/api/models"

# Local trust registry -- seed with orgs your team has already vetted, and
# any hashes flagged by prior incidents. This ships with a small honest
# starter set; extend trust_registry.json as your own pipeline scans more.
TRUST_REGISTRY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "trust_registry.json")


def load_trust_registry() -> dict:
    if not os.path.exists(TRUST_REGISTRY_PATH):
        return {"trusted_publishers": [], "known_bad_hashes": []}
    with open(TRUST_REGISTRY_PATH, encoding="utf-8") as f:
        return json.load(f)


def fetch_hf_metadata(model_ref: str) -> dict:
    """Query the Hugging Face Hub API for a model's public metadata.

    Returns an empty dict (never raises) on network failure or a non-HF
    ref, so provenance checks degrade to "unknown" instead of crashing the
    whole pipeline -- consistent with RiskWeave's "skip rather than guess"
    principle in parse_vulns.py.
    """
    try:
        resp = requests.get(f"{HF_API_BASE}/{model_ref}", timeout=10)
        if resp.status_code != 200:
            return {}
        return resp.json()
    except requests.RequestException:
        return {}


def save_provenance(conn, model_id: int, model_ref: str, metadata: dict, registry: dict):
    publisher = model_ref.split("/")[0] if "/" in model_ref else model_ref
    author_data = metadata.get("author") or publisher
    gated = bool(metadata.get("gated"))
    has_model_card = bool(metadata.get("cardData"))
    downloads = metadata.get("downloads")

    trust_match = publisher.lower() in {p.lower() for p in registry.get("trusted_publishers", [])}
    publisher_verified = bool(metadata.get("verified") or trust_match)

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO provenance_checks
                (model_id, publisher, publisher_verified, gated, has_model_card,
                 downloads_last_month, trust_registry_match, known_bad_hash_match)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (model_id, author_data, publisher_verified, gated, has_model_card,
             downloads, trust_match, False),
        )
    conn.commit()


def check_known_bad_hashes(conn, model_id: int, registry: dict):
    """After model_files have been scanned, mark provenance rows where a
    file's sha256 matches the known-bad list."""
    bad_hashes = {h.lower() for h in registry.get("known_bad_hashes", [])}
    if not bad_hashes:
        return 0
    with conn.cursor() as cur:
        cur.execute("SELECT sha256 FROM model_files WHERE model_id = %s", (model_id,))
        file_hashes = {row["sha256"].lower() for row in cur.fetchall() if row["sha256"]}
        if not (file_hashes & bad_hashes):
            return 0
        cur.execute(
            "UPDATE provenance_checks SET known_bad_hash_match = TRUE WHERE model_id = %s",
            (model_id,),
        )
    conn.commit()
    return len(file_hashes & bad_hashes)


def main():
    parser = argparse.ArgumentParser(description="Fetch and record provenance signal for a model")
    parser.add_argument("--model-ref", required=True, help="e.g. 'org/model-name'")
    parser.add_argument("--source", default="huggingface", choices=["huggingface", "local"])
    args = parser.parse_args()

    registry = load_trust_registry()
    conn = get_connection()
    try:
        model_id = upsert_model(conn, args.model_ref, args.source)
        record_scan(conn, scan_type="provenance", source_tool="huggingface-hub", target=args.model_ref)

        metadata = fetch_hf_metadata(args.model_ref) if args.source == "huggingface" else {}
        save_provenance(conn, model_id, args.model_ref, metadata, registry)
        n_bad = check_known_bad_hashes(conn, model_id, registry)

        if not metadata and args.source == "huggingface":
            print(f"Warning: no Hugging Face metadata found for '{args.model_ref}' "
                  f"(private repo, typo, or not on HF) -- recorded as unverified.", file=sys.stderr)
        print(f"Provenance recorded for '{args.model_ref}'"
              + (f" -- {n_bad} known-bad hash match(es)!" if n_bad else ""))
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
