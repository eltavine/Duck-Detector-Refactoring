#!/usr/bin/env python3
"""Verify the bounded production sampler using fake I/O; no real leak is triggered."""
from pathlib import Path
import shutil
import subprocess
import tempfile
root = Path(__file__).resolve().parent
probe = root.parents[1] / "main/cpp/nativeroot/probes"
with tempfile.TemporaryDirectory(prefix="wrapper-leak-test-") as directory:
    output = Path(directory) / "test"
    subprocess.run([shutil.which("c++") or "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    "-I", str(probe), str(probe / "ksu_wrapper_leak_probe.cpp"),
                    str(root / "ksu_wrapper_leak_probe_test.cpp"), "-o", str(output)], check=True)
    subprocess.run([str(output)], check=True, timeout=10)
print("Wrapper sampler ordering, budget, counter parsing, failure paths and cleanup passed")
