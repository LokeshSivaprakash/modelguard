"""
Walk a model directory (a local Hugging Face snapshot, or any folder of
weights) and classify every file by serialization format, then run the
pickle opcode scanner against anything that isn't safe-by-design.

Format classification matters because it's the difference between "this file
literally cannot execute code on load" and "this file needs scanning":

  safetensors  -- header-only JSON + raw tensor bytes, no executable opcodes
                  by construction. Hugging Face built the format specifically
                  to close the pickle RCE hole. Never flagged.
  onnx / gguf  -- protobuf / custom binary formats, not pickle-based. Lower
                  risk; not deep-scanned in this MVP (see README limitations).
  pt/pth/bin/
  ckpt/pkl     -- pickle-based (torch.save defaults to pickle protocol under
                  the hood for anything that isn't already a safetensors
                  file). Scanned with pickle_scanner.
  h5/hdf5      -- Keras/TF format. Can embed a Lambda layer carrying an
                  arbitrary serialized function; flagged as requires_scan but
                  not opcode-scanned in this MVP (different bytecode format,
                  future work -- see README roadmap).

Usage:
    python scan_model_files.py --model-ref org/model-name --path /path/to/snapshot
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ingestion.db import get_connection, upsert_model, record_scan
from ingestion.pickle_scanner import scan_file

FORMAT_BY_EXTENSION = {
    ".safetensors": ("safetensors", "safe_by_design"),
    ".onnx": ("onnx", "unscanned"),
    ".gguf": ("gguf", "unscanned"),
    ".pt": ("pytorch_legacy", "requires_scan"),
    ".pth": ("pytorch_legacy", "requires_scan"),
    ".bin": ("pytorch_legacy", "requires_scan"),
    ".ckpt": ("pytorch_legacy", "requires_scan"),
    ".pkl": ("pickle", "requires_scan"),
    ".pickle": ("pickle", "requires_scan"),
    ".joblib": ("pickle", "requires_scan"),
    ".h5": ("keras_h5", "unscanned"),
    ".hdf5": ("keras_h5", "unscanned"),
}

# Weight files only -- skip config.json, tokenizer files, README, etc.
WEIGHT_EXTENSIONS = set(FORMAT_BY_EXTENSION.keys())


def classify_file(path: str):
    _, ext = os.path.splitext(path)
    return FORMAT_BY_EXTENSION.get(ext.lower(), ("unknown", "unscanned"))


def upsert_model_file(conn, model_id: int, file_path: str, fmt: str, risk_class: str,
                       size_bytes: int, sha256: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO model_files (model_id, file_path, serialization_format,
                                      format_risk_class, file_size_bytes, sha256)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (model_id, file_path) DO UPDATE
            SET serialization_format = EXCLUDED.serialization_format,
                format_risk_class = EXCLUDED.format_risk_class,
                file_size_bytes = EXCLUDED.file_size_bytes,
                sha256 = EXCLUDED.sha256
            RETURNING id
            """,
            (model_id, file_path, fmt, risk_class, size_bytes, sha256),
        )
        return cur.fetchone()["id"]


def save_pickle_findings(conn, model_file_id: int, findings):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM pickle_findings WHERE model_file_id = %s", (model_file_id,))
        for f in findings:
            cur.execute(
                """
                INSERT INTO pickle_findings
                    (model_file_id, opcode, module_name, qualified_name,
                     risk_category, severity, byte_offset)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (model_file_id, f.opcode, f.module_name, f.qualified_name,
                 f.risk_category, f.severity, f.byte_offset),
            )
    conn.commit()


def scan_directory(conn, model_id: int, root: str) -> dict:
    stats = {"files_scanned": 0, "files_flagged": 0, "findings_total": 0}

    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            _, ext = os.path.splitext(filename)
            if ext.lower() not in WEIGHT_EXTENSIONS:
                continue

            fmt, risk_class = classify_file(full_path)
            size_bytes = os.path.getsize(full_path)

            if risk_class == "requires_scan":
                findings, sha256, _ = scan_file(full_path)
            else:
                findings = []
                with open(full_path, "rb") as fh:
                    sha256 = hashlib.sha256(fh.read()).hexdigest()

            rel_path = os.path.relpath(full_path, root)
            model_file_id = upsert_model_file(conn, model_id, rel_path, fmt, risk_class, size_bytes, sha256)
            save_pickle_findings(conn, model_file_id, findings)

            stats["files_scanned"] += 1
            if findings:
                stats["files_flagged"] += 1
                stats["findings_total"] += len(findings)

    return stats


def main():
    parser = argparse.ArgumentParser(description="Scan a model directory for unsafe serialization")
    parser.add_argument("--model-ref", required=True, help="e.g. 'org/model-name' or a local identifier")
    parser.add_argument("--path", required=True, help="Directory containing the model's weight files")
    parser.add_argument("--source", default="local", choices=["local", "huggingface"])
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Not a directory: {args.path}", file=sys.stderr)
        sys.exit(1)

    conn = get_connection()
    try:
        model_id = upsert_model(conn, args.model_ref, args.source)
        record_scan(conn, scan_type="model_file", source_tool="modelguard-pickle-scanner",
                    target=args.model_ref, raw_output_path=args.path)
        stats = scan_directory(conn, model_id, args.path)
        print(f"Scanned {stats['files_scanned']} files for '{args.model_ref}': "
              f"{stats['files_flagged']} flagged, {stats['findings_total']} findings total")
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
