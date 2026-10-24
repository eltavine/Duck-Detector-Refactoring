"""Compile the production timing sampler with fake counters and syscalls only."""

import shutil
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent
compiler = shutil.which("c++")
javac = shutil.which("javac")
if not compiler or not javac:
    raise RuntimeError("Host C++ compiler and JDK are required")
java_home = Path(javac).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="ksu-timing-test-") as directory:
    executable = Path(directory) / "sampler-test"
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-I",
            str(java_home / "include"),
            "-I",
            str(java_home / "include/linux"),
            str(root / "ksu_timing_probe_test.cpp"),
            "-o",
            str(executable),
        ],
        check=True,
    )
    subprocess.run([str(executable)], check=True, timeout=10)
print(
    "Timing sampler ordering, preflight, EINTR, UID, affinity and cleanup tests passed"
)
