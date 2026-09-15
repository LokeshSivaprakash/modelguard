"""
Static analysis of pickle-based model files for known-dangerous opcodes.

Pickle's GLOBAL/STACK_GLOBAL opcodes can reference *any* importable callable,
and REDUCE calls it with attacker-controlled arguments at load time. That is
the standard RCE primitive behind malicious PyTorch (.pt/.bin/.pth), Keras
Lambda-layer, and plain .pkl model files pulled from public hubs -- it is the
same technique documented by Trail of Bits' fickling and Hugging Face's own
picklescan, reimplemented here from scratch to actually understand it rather
than just call someone else's library.

This module NEVER unpickles/executes the file it scans. It disassembles the
opcode stream with the standard library's `pickletools.genops`, which reads
structure only -- the file's callables are inspected as strings, never
resolved or invoked. That distinction is the entire safety property of static
pickle scanning, and it's worth stating explicitly because getting it wrong
(e.g. calling pickle.load on an untrusted file "just to check") is exactly
the mistake this tool exists to prevent.

Known limitation, stated honestly rather than glossed over: this is a static,
single-pass opcode scan. A sufficiently determined adversary could interleave
MEMOIZE/PUT-based indirection between the string pushes and STACK_GLOBAL to
evade the naive two-slot pairing used here. Every static pickle scanner
(including production tools) shares this class of limitation; it is a reason
to pair static scanning with provenance/trust checks (see
ingestion/fetch_provenance.py), not a reason to skip static scanning.

Usage:
    python pickle_scanner.py path/to/model.pt
"""
import argparse
import hashlib
import pickletools
import sys
from dataclasses import dataclass
from typing import Optional

# (module, qualified_name) -> (risk_category, severity)
# Severity follows the same critical/high/medium/low vocabulary as
# RiskWeave's vulnerabilities.severity, so the two projects' findings can be
# reasoned about with one mental model.
DANGEROUS_CALLABLES = {
    ("os", "system"): ("code_execution", "critical"),
    ("os", "popen"): ("code_execution", "critical"),
    ("os", "execv"): ("code_execution", "critical"),
    ("os", "execve"): ("code_execution", "critical"),
    ("os", "execvp"): ("code_execution", "critical"),
    ("os", "spawnv"): ("code_execution", "critical"),
    ("nt", "system"): ("code_execution", "critical"),
    ("posix", "system"): ("code_execution", "critical"),
    ("subprocess", "Popen"): ("code_execution", "critical"),
    ("subprocess", "call"): ("code_execution", "critical"),
    ("subprocess", "run"): ("code_execution", "critical"),
    ("subprocess", "check_call"): ("code_execution", "critical"),
    ("subprocess", "check_output"): ("code_execution", "critical"),
    ("builtins", "eval"): ("code_execution", "critical"),
    ("builtins", "exec"): ("code_execution", "critical"),
    ("builtins", "compile"): ("code_execution", "high"),
    ("builtins", "__import__"): ("code_execution", "high"),
    ("builtins", "getattr"): ("code_execution", "medium"),
    ("pickle", "loads"): ("deserialization", "high"),
    ("pickle", "load"): ("deserialization", "high"),
    ("marshal", "loads"): ("deserialization", "high"),
    ("shutil", "rmtree"): ("filesystem", "high"),
    ("shutil", "copy"): ("filesystem", "medium"),
    ("socket", "socket"): ("network_egress", "high"),
    ("socket", "create_connection"): ("network_egress", "high"),
    ("urllib.request", "urlopen"): ("network_egress", "high"),
    ("http.client", "HTTPConnection"): ("network_egress", "high"),
    ("requests.api", "get"): ("network_egress", "high"),
    ("requests.api", "post"): ("network_egress", "high"),
    ("ctypes", "CDLL"): ("code_execution", "critical"),
    ("webbrowser", "open"): ("code_execution", "medium"),
    ("importlib", "import_module"): ("code_execution", "medium"),
}

# Any GLOBAL/STACK_GLOBAL reference into one of these modules gets flagged
# even if the specific callable isn't in the table above -- catches
# variants (os.getenv, sys.modules tampering, etc.) we haven't enumerated.
SUSPICIOUS_MODULES = {
    "os", "nt", "posix", "subprocess", "sys", "builtins", "socket",
    "shutil", "ctypes", "importlib", "pty", "platform", "code",
}

STRING_PUSH_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING",
}

INFORMATIONAL_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}


@dataclass
class Finding:
    opcode: str
    module_name: Optional[str]
    qualified_name: Optional[str]
    risk_category: str
    severity: str
    byte_offset: int

    def as_dict(self):
        return {
            "opcode": self.opcode,
            "module_name": self.module_name,
            "qualified_name": self.qualified_name,
            "risk_category": self.risk_category,
            "severity": self.severity,
            "byte_offset": self.byte_offset,
        }


def _classify(module: str, qualname: str):
    key = (module, qualname)
    if key in DANGEROUS_CALLABLES:
        return DANGEROUS_CALLABLES[key]
    top_level = module.split(".")[0]
    if module in SUSPICIOUS_MODULES or top_level in SUSPICIOUS_MODULES:
        return ("suspicious_import", "medium")
    return None


def scan_pickle_bytes(data: bytes) -> list[Finding]:
    """Disassemble a pickle byte stream and return every dangerous reference found.

    Never calls pickle.load / pickle.loads on `data`.
    """
    findings: list[Finding] = []
    pending_strings: list[str] = []

    for opcode, arg, pos in pickletools.genops(data):
        name = opcode.name

        if name in STRING_PUSH_OPS:
            pending_strings.append(arg)
            pending_strings = pending_strings[-2:]
            continue

        if name == "GLOBAL":
            # Protocol 0-2: arg is a single "module qualname" string.
            module, _, qualname = str(arg).partition(" ")
            classification = _classify(module, qualname)
            if classification:
                category, severity = classification
                findings.append(Finding("GLOBAL", module, qualname, category, severity, pos))

        elif name == "STACK_GLOBAL":
            # Protocol 4+: module/qualname are the two preceding string pushes.
            if len(pending_strings) >= 2:
                module, qualname = pending_strings[-2], pending_strings[-1]
            else:
                module, qualname = "<unresolved>", "<unresolved>"
            classification = _classify(module, qualname)
            if classification:
                category, severity = classification
                findings.append(Finding("STACK_GLOBAL", module, qualname, category, severity, pos))

        elif name in INFORMATIONAL_OPS:
            # REDUCE/BUILD/etc. are only interesting as corroborating context
            # for a nearby GLOBAL finding -- not flagged standalone, since
            # they're used constantly by entirely benign pickled objects
            # (every dataclass, every numpy array, ...).
            pass

        # Any non-string opcode between two string pushes and a STACK_GLOBAL
        # would break real-world pairing; in practice the pickler always
        # emits the two pushes immediately before STACK_GLOBAL, so we don't
        # need to explicitly clear pending_strings here.

    return findings


def scan_file(path: str) -> tuple[list[Finding], str, int]:
    """Scan a file on disk. Returns (findings, sha256_hex, size_bytes)."""
    with open(path, "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    findings = scan_pickle_bytes(data)
    return findings, digest, len(data)


def main():
    parser = argparse.ArgumentParser(description="Static opcode scan of a pickle-based model file")
    parser.add_argument("path", help="Path to a .pt/.pth/.bin/.pkl/.ckpt file")
    args = parser.parse_args()

    findings, digest, size = scan_file(args.path)
    print(f"{args.path}  ({size} bytes, sha256={digest[:16]}...)")
    if not findings:
        print("  No dangerous opcode references found.")
        return

    for f in findings:
        print(f"  [{f.severity.upper():8s}] {f.opcode} -> {f.module_name}.{f.qualified_name} "
              f"({f.risk_category}) @ offset {f.byte_offset}")
    sys.exit(1 if any(f.severity in ("critical", "high") for f in findings) else 0)


if __name__ == "__main__":
    main()
