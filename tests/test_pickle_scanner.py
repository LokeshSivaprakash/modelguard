"""
Unit tests for the pickle opcode scanner. Fixtures are generated in-process
via pickle.dumps() with a custom __reduce__ -- this is safe: __reduce__ is
called at dump time to decide *what to serialize*, it does not execute the
callable it references. os.system is never actually invoked by these tests.
"""
import os
import pickle
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ingestion.pickle_scanner import scan_pickle_bytes


class _EvilOsSystem:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


class _EvilSubprocess:
    def __reduce__(self):
        return (subprocess.Popen, (["ls"],))


class _Benign:
    def __init__(self):
        self.weights = [1, 2, 3]
        self.name = "benign-layer"


def test_detects_os_system_protocol_2():
    data = pickle.dumps(_EvilOsSystem(), protocol=2)
    findings = scan_pickle_bytes(data)
    assert any(f.qualified_name == "system" and f.risk_category == "code_execution" for f in findings)
    assert any(f.severity == "critical" for f in findings)


def test_detects_os_system_protocol_4_stack_global():
    data = pickle.dumps(_EvilOsSystem(), protocol=4)
    findings = scan_pickle_bytes(data)
    assert any(f.opcode == "STACK_GLOBAL" and f.qualified_name == "system" for f in findings)


def test_detects_subprocess_popen():
    data = pickle.dumps(_EvilSubprocess(), protocol=4)
    findings = scan_pickle_bytes(data)
    assert any(f.module_name == "subprocess" and f.qualified_name == "Popen" for f in findings)
    assert any(f.severity == "critical" for f in findings)


def test_benign_object_produces_no_findings():
    data = pickle.dumps(_Benign(), protocol=4)
    findings = scan_pickle_bytes(data)
    assert findings == []


def test_never_executes_the_payload(capsys):
    """The whole safety property: scanning must not run os.system.
    If it did, this test's own working directory would show side effects
    (or in CI, the command would actually run) -- instead we assert the
    scan completes and returns structured findings without any exec.
    """
    data = pickle.dumps(_EvilOsSystem(), protocol=4)
    # If scan_pickle_bytes ever called pickle.loads() internally, this
    # would actually execute `echo pwned` and print to stdout during the
    # test run. It must not.
    findings = scan_pickle_bytes(data)
    captured = capsys.readouterr()
    assert "pwned" not in captured.out
    assert len(findings) > 0
