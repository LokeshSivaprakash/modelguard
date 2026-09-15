"""Shared Postgres connection helper for all ingestion modules.

Deliberately identical in shape to RiskWeave's ingestion/db.py -- same DSN
env var pattern, same RealDictCursor choice -- so the two projects read as
one author's consistent toolkit, not two unrelated codebases.
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

DB_DSN = os.environ.get(
    "MODELGUARD_DB_DSN",
    "dbname=modelguard user=modelguard password=modelguard host=localhost port=5432",
)


def get_connection():
    """Return a new psycopg2 connection. Caller is responsible for closing it."""
    return psycopg2.connect(DB_DSN, cursor_factory=RealDictCursor)


def record_scan(conn, scan_type: str, source_tool: str, target: str, raw_output_path: str = None) -> int:
    """Log a scan event and return its id, for audit trail purposes."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scans (scan_type, source_tool, target, raw_output_path)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (scan_type, source_tool, target, raw_output_path),
        )
        scan_id = cur.fetchone()["id"]
    conn.commit()
    return scan_id


def upsert_model(conn, model_ref: str, source: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO models (model_ref, source, last_scanned)
            VALUES (%s, %s, now())
            ON CONFLICT (model_ref)
            DO UPDATE SET last_scanned = now()
            RETURNING id
            """,
            (model_ref, source),
        )
        model_id = cur.fetchone()["id"]
    conn.commit()
    return model_id
