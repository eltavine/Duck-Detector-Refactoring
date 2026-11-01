#!/usr/bin/env python3
"""Compile the production sampler and verify its controls and failure paths on a POSIX host."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
PROBE = ROOT.parents[1] / "main/cpp/nativeroot/probes"
compiler = shutil.which("c++")
if not compiler:
    raise RuntimeError("A host C++ compiler is required")
with tempfile.TemporaryDirectory(prefix="initrc-timing-host-") as directory:
    executable = Path(directory) / "sampler-test"
    subprocess.run([
        compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread", "-I", str(PROBE),
        str(PROBE / "initrc_timing_probe.cpp"), str(ROOT / "initrc_timing_probe_test.cpp"),
        "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True, timeout=20)
print("init.rc sampler balance, worker isolation, failure states, budget and cleanup passed")
