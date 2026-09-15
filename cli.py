#!/usr/bin/env python3
"""
ModelGuard CLI -- one entry point for the whole pipeline.

Examples:
    python cli.py init-db
    python cli.py scan-model --model-ref demo/toy-classifier --path ./demo/fixtures --source local
    python cli.py check-provenance --model-ref bert-base-uncased
    python cli.py scan-pipeline --pipeline-ref inference-service:latest
    python cli.py correlate
    python cli.py narrate --limit 5
    python cli.py report
    python cli.py aibom --model-ref demo/toy-classifier
    python cli.py dashboard
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

import click
from rich.console import Console
from rich.table import Table

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingestion.db import get_connection
from ingestion import scan_model_files, fetch_provenance, parse_pipeline_sbom, parse_pipeline_vulns
from correlation import aibom_risk

console = Console()


def _require_tool(name: str):
    if shutil.which(name) is None:
        console.print(f"[red]'{name}' not found on PATH.[/red] Install it and try again.")
        sys.exit(1)


def _run(cmd: list, **kwargs):
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    return subprocess.run(cmd, check=True, **kwargs)


@click.group()
def cli():
    """ModelGuard -- AI/ML supply-chain risk scanner. RiskWeave's correlation
    engine, applied to model artifacts instead of container images."""
    pass


@cli.command("init-db")
def init_db():
    """Apply schema.sql against the configured Postgres database."""
    schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    conn = get_connection()
    try:
        with open(schema_path, encoding="utf-8") as f:
            sql = f.read()
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
        console.print("[green]Schema applied successfully.[/green]")
    finally:
        conn.close()


@cli.command("scan-model")
@click.option("--model-ref", required=True, help="e.g. 'org/model-name' or a local identifier")
@click.option("--path", required=True, help="Directory containing the model's weight files")
@click.option("--source", default="local", type=click.Choice(["local", "huggingface"]))
def scan_model(model_ref, path, source):
    """Classify and scan every weight file under --path for unsafe serialization."""
    conn = get_connection()
    try:
        from ingestion.db import upsert_model, record_scan
        model_id = upsert_model(conn, model_ref, source)
        record_scan(conn, scan_type="model_file", source_tool="modelguard-pickle-scanner",
                    target=model_ref, raw_output_path=path)
        stats = scan_model_files.scan_directory(conn, model_id, path)
        console.print(f"[green]Scanned {stats['files_scanned']} files: "
                       f"{stats['files_flagged']} flagged, {stats['findings_total']} findings total[/green]")
    finally:
        conn.close()


@cli.command("check-provenance")
@click.option("--model-ref", required=True)
@click.option("--source", default="huggingface", type=click.Choice(["huggingface", "local"]))
def check_provenance(model_ref, source):
    """Fetch publisher/provenance signal and cross-check the trust registry."""
    registry = fetch_provenance.load_trust_registry()
    conn = get_connection()
    try:
        from ingestion.db import upsert_model, record_scan
        model_id = upsert_model(conn, model_ref, source)
        record_scan(conn, scan_type="provenance", source_tool="huggingface-hub", target=model_ref)
        metadata = fetch_provenance.fetch_hf_metadata(model_ref) if source == "huggingface" else {}
        fetch_provenance.save_provenance(conn, model_id, model_ref, metadata, registry)
        n_bad = fetch_provenance.check_known_bad_hashes(conn, model_id, registry)
        msg = f"[green]Provenance recorded for '{model_ref}'[/green]"
        if n_bad:
            msg += f" [red]-- {n_bad} known-bad hash match(es)![/red]"
        console.print(msg)
    finally:
        conn.close()


@cli.command("scan-pipeline")
@click.option("--pipeline-ref", required=True, help="e.g. inference-service:1.4.0")
@click.option("--target", default=None, help="Image ref or dir: path for Syft/Grype (defaults to --pipeline-ref)")
def scan_pipeline(pipeline_ref, target):
    """Scan the ML pipeline/inference environment with Syft + Grype (same tools RiskWeave uses)."""
    _require_tool("syft")
    _require_tool("grype")
    scan_target = target or pipeline_ref

    with tempfile.TemporaryDirectory() as tmp:
        sbom_path = os.path.join(tmp, "pipeline_sbom.json")
        vulns_path = os.path.join(tmp, "pipeline_vulns.json")

        console.print(f"[cyan]Generating SBOM for {scan_target}...[/cyan]")
        with open(sbom_path, "w", encoding="utf-8") as f:
            _run(["syft", scan_target, "-o", "syft-json"], stdout=f)

        console.print(f"[cyan]Scanning {scan_target} for vulnerabilities...[/cyan]")
        with open(vulns_path, "w", encoding="utf-8") as f:
            _run(["grype", scan_target, "-o", "json"], stdout=f)

        conn = get_connection()
        try:
            n_deps = parse_pipeline_sbom.load_pipeline_sbom(conn, pipeline_ref, sbom_path)
            n_vulns, n_skipped = parse_pipeline_vulns.load_pipeline_vulns(conn, pipeline_ref, vulns_path)
        finally:
            conn.close()

        console.print(f"[green]Loaded {n_deps} dependencies, {n_vulns} vulnerabilities "
                       f"({n_skipped} skipped) for {pipeline_ref}[/green]")


@cli.command("correlate")
def correlate():
    """Run the correlation engine against everything loaded so far."""
    conn = get_connection()
    try:
        n = aibom_risk.run_correlation(conn)
        console.print(f"[green]Scored {n} models.[/green]")
    finally:
        conn.close()
    _print_report(limit=10)


@cli.command("narrate")
@click.option("--limit", default=5)
def narrate(limit):
    """Generate AI plain-English narratives for the top unresolved findings."""
    if not os.environ.get("OPENAI_API_KEY"):
        console.print("[red]OPENAI_API_KEY not set in your environment/.env file.[/red]")
        sys.exit(1)

    from ai_layer import risk_narrative
    conn = get_connection()
    try:
        findings = risk_narrative.fetch_unresolved(conn, limit)
        if not findings:
            console.print("[yellow]No unresolved findings above the score threshold yet. "
                           "Run 'cli.py correlate' first.[/yellow]")
            return
        for f in findings:
            console.print(f"\n[bold]{f['model_ref']}[/bold] (score {f['risk_score']:.1f})")
            narrative_text = risk_narrative.generate_narrative(f)
            console.print(narrative_text)
            risk_narrative.save_narrative(conn, f["id"], narrative_text)
    finally:
        conn.close()


def _print_report(limit: int = 10):
    conn = get_connection()
    try:
        rows = aibom_risk.top_findings(conn, limit)
    finally:
        conn.close()

    if not rows:
        console.print("[yellow]No findings yet. Run 'cli.py correlate' first.[/yellow]")
        return

    table = Table(title="ModelGuard — Top AI Supply-Chain Risks")
    table.add_column("Score", justify="right", style="bold")
    table.add_column("Model")
    table.add_column("MITRE ATLAS")
    table.add_column("Why", overflow="fold")

    for row in rows:
        score = row["risk_score"]
        color = "red" if score >= 8 else "yellow" if score >= 5 else "white"
        table.add_row(
            f"[{color}]{score:.1f}[/{color}]",
            row["model_ref"],
            row["mitre_atlas_technique"] or "-",
            row["reasoning"],
        )
    console.print(table)


@cli.command("report")
@click.option("--limit", default=10)
def report(limit):
    """Print current top findings (no re-correlation)."""
    _print_report(limit)


@cli.command("aibom")
@click.option("--model-ref", required=True)
@click.option("--out", default=None, help="Output path (defaults to stdout)")
def aibom(model_ref, out):
    """Export a machine-readable AI Bill of Materials for one model."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, model_ref, source, first_seen, last_scanned FROM models WHERE model_ref = %s",
                        (model_ref,))
            model = cur.fetchone()
            if not model:
                console.print(f"[red]No model found for '{model_ref}'. Run scan-model first.[/red]")
                sys.exit(1)

            cur.execute("SELECT file_path, serialization_format, format_risk_class, sha256, file_size_bytes "
                        "FROM model_files WHERE model_id = %s", (model["id"],))
            files = cur.fetchall()

            cur.execute(
                "SELECT pf.opcode, pf.module_name, pf.qualified_name, pf.risk_category, pf.severity, "
                "mf.file_path FROM pickle_findings pf JOIN model_files mf ON pf.model_file_id = mf.id "
                "WHERE mf.model_id = %s", (model["id"],)
            )
            findings = cur.fetchall()

            cur.execute("SELECT * FROM provenance_checks WHERE model_id = %s ORDER BY checked_at DESC LIMIT 1",
                        (model["id"],))
            provenance = cur.fetchone()

            cur.execute("SELECT risk_score, reasoning, owasp_llm_category, mitre_atlas_technique "
                        "FROM aibom_findings WHERE model_id = %s", (model["id"],))
            risk = cur.fetchone()
    finally:
        conn.close()

    doc = {
        "aibom_version": "0.1",
        "model": dict(model, first_seen=str(model["first_seen"]), last_scanned=str(model["last_scanned"])),
        "files": [dict(f) for f in files],
        "pickle_findings": [dict(f) for f in findings],
        "provenance": dict(provenance) if provenance else None,
        "risk": dict(risk) if risk else None,
    }
    output = json.dumps(doc, indent=2, default=str)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(output)
        console.print(f"[green]AIBOM written to {out}[/green]")
    else:
        print(output)


@cli.command("dashboard")
@click.option("--port", default=5060)
@click.option("--host", default="127.0.0.1")
def dashboard(port, host):
    """Launch the web dashboard."""
    os.environ.setdefault("FLASK_RUN_PORT", str(port))
    from dashboard.app import app
    console.print(f"[green]Dashboard running at http://{host}:{port}[/green]")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    cli()
