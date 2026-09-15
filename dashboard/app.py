"""
Server-rendered dashboard for ModelGuard findings -- Flask + Jinja, no build
step, no JS framework. Same deliberate choice RiskWeave's dashboard makes:
the point of this project is the correlation logic underneath, not the
frontend.
"""
import os
import sys

from flask import Flask, render_template, request, redirect, url_for

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ingestion.db import get_connection

app = Flask(__name__)


@app.route("/")
def index():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM models")
            n_models = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM pickle_findings WHERE severity IN ('critical','high')")
            n_critical_findings = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM aibom_findings WHERE resolved = FALSE AND risk_score >= 7.0")
            n_blocking = cur.fetchone()["n"]

            cur.execute("SELECT COUNT(*) AS n FROM provenance_checks WHERE known_bad_hash_match = TRUE")
            n_known_bad = cur.fetchone()["n"]

            show_resolved = request.args.get("show_resolved") == "1"
            sort = request.args.get("sort", "risk_score")
            sort_col = {"risk_score": "af.risk_score", "model": "m.model_ref"}.get(sort, "af.risk_score")

            query = f"""
                SELECT af.id, af.risk_score, af.reasoning, af.owasp_llm_category,
                       af.mitre_atlas_technique, af.resolved, m.model_ref, m.source
                FROM aibom_findings af
                JOIN models m ON m.id = af.model_id
                {"" if show_resolved else "WHERE af.resolved = FALSE"}
                ORDER BY {sort_col} DESC
            """
            cur.execute(query)
            findings = cur.fetchall()
    finally:
        conn.close()

    return render_template(
        "index.html",
        n_models=n_models,
        n_critical_findings=n_critical_findings,
        n_blocking=n_blocking,
        n_known_bad=n_known_bad,
        findings=findings,
        show_resolved=show_resolved,
        sort=sort,
    )


@app.route("/resolve/<int:finding_id>", methods=["POST"])
def resolve(finding_id):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE aibom_findings SET resolved = TRUE WHERE id = %s", (finding_id,))
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("FLASK_RUN_PORT", 5060)))
