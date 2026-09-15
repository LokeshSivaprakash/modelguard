-- ModelGuard core schema
-- Models the AI/ML supply-chain graph: model artifact -> serialized file -> pickle
-- opcode findings, plus model -> publisher provenance, plus the ML pipeline's own
-- dependency -> CVE graph (the same shape RiskWeave uses for containers).
--
-- The goal, same as RiskWeave: don't just store scanner output. Normalize enough
-- that a single JOIN answers "does this model contain a code-execution primitive,
-- from an unverified publisher, that a vulnerable loader would happily deserialize?"
-- That correlation -- not the opcode scan alone -- is the product.

CREATE TABLE IF NOT EXISTS scans (
    id              SERIAL PRIMARY KEY,
    scan_type       TEXT NOT NULL,          -- 'model_file' | 'provenance' | 'pipeline_sbom' | 'pipeline_vuln'
    source_tool     TEXT NOT NULL,          -- 'modelguard-pickle-scanner' | 'huggingface-hub' | 'syft' | 'grype'
    target          TEXT NOT NULL,          -- model ref or local path
    raw_output_path TEXT,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- One row per model we've seen (a Hugging Face repo, or a local directory of weights)
CREATE TABLE IF NOT EXISTS models (
    id              SERIAL PRIMARY KEY,
    model_ref       TEXT UNIQUE NOT NULL,   -- e.g. 'org/model-name' or a local path
    source          TEXT NOT NULL,          -- 'huggingface' | 'local'
    first_seen      TIMESTAMPTZ DEFAULT now(),
    last_scanned    TIMESTAMPTZ
);

-- Individual serialized files that make up a model (a repo is usually several files)
CREATE TABLE IF NOT EXISTS model_files (
    id                      SERIAL PRIMARY KEY,
    model_id                INTEGER REFERENCES models(id) ON DELETE CASCADE,
    file_path               TEXT NOT NULL,
    serialization_format    TEXT NOT NULL,   -- 'safetensors' | 'pickle' | 'pytorch_legacy' | 'keras_h5' | 'onnx' | 'gguf' | 'unknown'
    format_risk_class       TEXT NOT NULL,   -- 'safe_by_design' | 'requires_scan' | 'unscanned'
    file_size_bytes         BIGINT,
    sha256                  TEXT,
    UNIQUE (model_id, file_path)
);

-- Dangerous opcodes/callables found by disassembling a pickle-based file
-- (pickletools.genops -- the file is never unpickled/executed to scan it)
CREATE TABLE IF NOT EXISTS pickle_findings (
    id                  SERIAL PRIMARY KEY,
    model_file_id       INTEGER REFERENCES model_files(id) ON DELETE CASCADE,
    opcode              TEXT NOT NULL,       -- 'GLOBAL' | 'STACK_GLOBAL' | 'REDUCE' | 'INST' | 'OBJ' | 'NEWOBJ'
    module_name         TEXT,                -- e.g. 'os', 'subprocess', 'builtins'
    qualified_name       TEXT,                -- e.g. 'os.system', 'subprocess.Popen'
    risk_category        TEXT NOT NULL,       -- 'code_execution' | 'network_egress' | 'filesystem' | 'suspicious_import' | 'deserialization'
    severity             TEXT NOT NULL,       -- 'critical' | 'high' | 'medium' | 'low'
    byte_offset           BIGINT,
    detected_at           TIMESTAMPTZ DEFAULT now()
);

-- Publisher / trust checks for a model, mostly sourced from the Hugging Face Hub API
-- plus a local trust registry of known-good publishers and known-bad hashes.
CREATE TABLE IF NOT EXISTS provenance_checks (
    id                     SERIAL PRIMARY KEY,
    model_id               INTEGER REFERENCES models(id) ON DELETE CASCADE,
    publisher              TEXT,
    publisher_verified     BOOLEAN DEFAULT FALSE,   -- HF "verified org" style signal
    gated                  BOOLEAN DEFAULT FALSE,
    has_model_card         BOOLEAN DEFAULT FALSE,
    downloads_last_month   INTEGER,
    trust_registry_match   BOOLEAN DEFAULT FALSE,   -- publisher/hash on our own allow-list
    known_bad_hash_match   BOOLEAN DEFAULT FALSE,   -- file hash on our own deny-list
    checked_at             TIMESTAMPTZ DEFAULT now()
);

-- The ML pipeline's own dependencies, scanned the same way RiskWeave scans a
-- container image -- via Syft against the environment that will *load* the model.
CREATE TABLE IF NOT EXISTS pipeline_dependencies (
    id              SERIAL PRIMARY KEY,
    pipeline_ref    TEXT NOT NULL,          -- e.g. 'inference-service:latest' or a requirements.txt path
    package_name    TEXT NOT NULL,
    version         TEXT NOT NULL,
    ecosystem       TEXT,
    UNIQUE (pipeline_ref, package_name, version)
);

CREATE TABLE IF NOT EXISTS pipeline_vulnerabilities (
    id                  SERIAL PRIMARY KEY,
    dependency_id       INTEGER REFERENCES pipeline_dependencies(id) ON DELETE CASCADE,
    cve_id              TEXT NOT NULL,
    severity            TEXT,
    cvss_score          NUMERIC,
    fixed_version       TEXT,
    UNIQUE (dependency_id, cve_id)
);

-- Materialized correlation output: what the AI layer and dashboard read from.
-- One row per model, same idea as RiskWeave's toxic_combinations -- the score
-- reflects the worst correlated combination found for that model, not just
-- the worst individual finding.
CREATE TABLE IF NOT EXISTS aibom_findings (
    id                      SERIAL PRIMARY KEY,
    model_id                INTEGER REFERENCES models(id) ON DELETE CASCADE,
    -- ON DELETE SET NULL: aibom_findings is a derived/recomputed table, not
    -- a source of truth. Without this, re-scanning a model that already has
    -- a correlated finding fails with a FK violation the moment
    -- scan_model_files.py tries to delete and replace its stale
    -- pickle_findings rows -- caught by actually re-running the pipeline
    -- against the same model twice, which is the normal CI usage pattern
    -- (every PR re-scans). correlate() repopulates this pointer regardless.
    worst_pickle_finding_id INTEGER REFERENCES pickle_findings(id) ON DELETE SET NULL,
    risk_score              NUMERIC NOT NULL,
    reasoning                TEXT,
    owasp_llm_category        TEXT,            -- e.g. 'LLM03:2025 Supply Chain'
    mitre_atlas_technique     TEXT,            -- e.g. 'AML.T0010.003 (AI Supply Chain Compromise: Model)'
    detected_at               TIMESTAMPTZ DEFAULT now(),
    resolved                  BOOLEAN DEFAULT FALSE,
    UNIQUE (model_id)
);

CREATE INDEX IF NOT EXISTS idx_pickle_severity ON pickle_findings(severity);
CREATE INDEX IF NOT EXISTS idx_aibom_score ON aibom_findings(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_provenance_model ON provenance_checks(model_id);
