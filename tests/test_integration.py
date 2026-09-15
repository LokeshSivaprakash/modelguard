"""
Integration tests against a REAL Postgres database -- same convention as
RiskWeave's tests/test_integration.py. These prove the whole pipeline works
end to end (scan -> provenance -> correlate, including re-running it), not
just the scoring math in isolation.

Skipped automatically if no database is reachable, so `pytest` still runs
clean for someone who only wants the fast unit tests. To run them:

    docker run --rm -d -p 5432:5432 -e POSTGRES_DB=modelguard_test \
        -e POSTGRES_USER=modelguard -e POSTGRES_PASSWORD=modelguard \
        --name mg_test_db postgres:16
    export MODELGUARD_TEST_DSN="dbname=modelguard_test user=modelguard password=modelguard host=localhost port=5432"
    pytest tests/test_integration.py -v

Includes a regression test for a real bug found while dogfooding this
project: re-scanning a model that already had a correlated finding failed
with a foreign-key violation, because aibom_findings.worst_pickle_finding_id
had no ON DELETE behavior and scan_model_files.py deletes+replaces
pickle_findings on every scan. Fixed in schema.sql with ON DELETE SET NULL.
"""
import os
import pickle
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "schema.sql")
TEST_DSN = os.environ.get("MODELGUARD_TEST_DSN")

pytestmark = pytest.mark.skipif(
    not TEST_DSN, reason="MODELGUARD_TEST_DSN not set; skipping DB integration tests"
)


@pytest.fixture
def conn(tmp_path):
    import psycopg2
    from psycopg2.extras import RealDictCursor

    os.environ["MODELGUARD_DB_DSN"] = TEST_DSN

    connection = psycopg2.connect(TEST_DSN, cursor_factory=RealDictCursor)
    with open(SCHEMA_PATH) as f:
        schema = f.read()
    with connection.cursor() as cur:
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        cur.execute(schema)
    connection.commit()
    yield connection
    connection.close()


@pytest.fixture
def malicious_model_dir(tmp_path):
    """A model directory with one file that trips the pickle scanner --
    built the same safe way demo/make_demo_fixtures.py does (pickle.dumps
    calls __reduce__ at dump time, never at scan time)."""
    class _Evil:
        def __reduce__(self):
            import os as os_module
            return (os_module.system, ("echo pwned",))

    model_dir = tmp_path / "toy-model"
    model_dir.mkdir()
    with open(model_dir / "pytorch_model.bin", "wb") as f:
        pickle.dump(_Evil(), f, protocol=2)
    return str(model_dir)


def test_scan_and_correlate_end_to_end(conn, malicious_model_dir):
    from ingestion.db import upsert_model
    from ingestion import scan_model_files
    from correlation import aibom_risk

    model_id = upsert_model(conn, "test/malicious-model", "local")
    stats = scan_model_files.scan_directory(conn, model_id, malicious_model_dir)
    assert stats["files_flagged"] == 1

    aibom_risk.run_correlation(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT risk_score FROM aibom_findings WHERE model_id = %s", (model_id,))
        row = cur.fetchone()
    assert float(row["risk_score"]) >= 7.0  # code-execution + unverified provenance


def test_rescan_does_not_break_on_foreign_key(conn, malicious_model_dir):
    """Regression test for the FK-violation bug: scanning the same model
    twice, with a correlate() in between, must succeed both times."""
    from ingestion.db import upsert_model
    from ingestion import scan_model_files
    from correlation import aibom_risk

    model_id = upsert_model(conn, "test/malicious-model", "local")

    scan_model_files.scan_directory(conn, model_id, malicious_model_dir)
    aibom_risk.run_correlation(conn)

    # This second scan is what used to raise psycopg2.errors.ForeignKeyViolation.
    stats = scan_model_files.scan_directory(conn, model_id, malicious_model_dir)
    assert stats["files_flagged"] == 1

    aibom_risk.run_correlation(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM aibom_findings WHERE model_id = %s", (model_id,))
        assert cur.fetchone()["n"] == 1  # correlate is idempotent, not additive


def test_clean_model_scores_low_end_to_end(conn, tmp_path):
    from ingestion.db import upsert_model
    from ingestion import scan_model_files
    from correlation import aibom_risk

    model_dir = tmp_path / "clean-model"
    model_dir.mkdir()
    with open(model_dir / "model.safetensors", "wb") as f:
        f.write(b'{"metadata":{}}' + b"\x00" * 16)

    model_id = upsert_model(conn, "test/clean-model", "local")
    stats = scan_model_files.scan_directory(conn, model_id, str(model_dir))
    assert stats["files_flagged"] == 0

    aibom_risk.run_correlation(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT risk_score FROM aibom_findings WHERE model_id = %s", (model_id,))
        row = cur.fetchone()
    # still scores > 0 (no provenance checked yet is itself a finding), but
    # well below the CI gate's 7.0 block threshold
    assert float(row["risk_score"]) < 7.0