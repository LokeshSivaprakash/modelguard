"""
Turns an aibom_findings row into a plain-English narrative + remediation plan
-- same role, and same prompt-engineering approach, as RiskWeave's
ai_layer/risk_narrative.py. Requires OPENAI_API_KEY in the environment.

Usage:
    python risk_narrative.py --limit 5
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from openai import OpenAI
from ingestion.db import get_connection

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

SYSTEM_PROMPT = """You are a security analyst assistant reviewing AI/ML supply-chain \
findings. You are given a single correlated finding about a model artifact: what was \
found in its serialized weights, its publisher provenance, and any CVEs in the pipeline \
that will load it. Write:
1. A one-paragraph plain-English explanation of why this specific combination is \
   dangerous -- explain the actual attack path (what would need to happen for this to \
   be exploited), not a generic "this could be risky" statement.
2. A ranked, concrete remediation plan (2-4 steps), most impactful first.
3. The single most relevant MITRE ATLAS technique and OWASP LLM Top 10 (2025) category, \
   if not already given correctly.

Be direct and specific. No generic security advice ("verify your sources"). Reference \
the actual model, callable, and publisher given to you."""


def fetch_unresolved(conn, limit: int):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT af.id, af.risk_score, af.reasoning, af.owasp_llm_category,
                   af.mitre_atlas_technique, m.model_ref, m.source
            FROM aibom_findings af
            JOIN models m ON m.id = af.model_id
            WHERE af.resolved = FALSE AND af.risk_score >= 6.0
            ORDER BY af.risk_score DESC
            LIMIT %s
            """,
            (limit,),
        )
        return cur.fetchall()


def generate_narrative(finding: dict) -> str:
    user_prompt = (
        f"Model: {finding['model_ref']} (source: {finding['source']})\n"
        f"Risk score: {finding['risk_score']}\n"
        f"Correlated facts: {finding['reasoning']}\n"
        f"Preliminary OWASP LLM category: {finding['owasp_llm_category']}\n"
        f"Preliminary MITRE ATLAS mapping: {finding['mitre_atlas_technique']}\n"
    )
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=500,
    )
    return response.choices[0].message.content


def save_narrative(conn, finding_id: int, narrative: str):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE aibom_findings SET reasoning = %s WHERE id = %s",
            (narrative, finding_id),
        )
    conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Generate AI narratives for top unresolved model findings")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set. Add it to your .env file.", file=sys.stderr)
        sys.exit(1)

    conn = get_connection()
    try:
        findings = fetch_unresolved(conn, args.limit)
        if not findings:
            print("No unresolved findings above risk score 6.0.")
            return

        for f in findings:
            print(f"\n=== {f['model_ref']} (score {f['risk_score']:.1f}) ===")
            narrative = generate_narrative(f)
            print(narrative)
            if not args.dry_run:
                save_narrative(conn, f["id"], narrative)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
