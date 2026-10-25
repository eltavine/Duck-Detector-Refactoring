"""Compile the production timing sampler with fake counters and syscalls only."""

import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent
compiler = shutil.which("c++")
javac = shutil.which("javac")
if not compiler or not javac:
    raise RuntimeError("Host C++ compiler and JDK are required")
java_home = Path(os.environ.get("JAVA_HOME") or (
    subprocess.check_output(["/usr/libexec/java_home"], text=True).strip()
    if platform.system() == "Darwin" else str(Path(javac).resolve().parent.parent)
))
jni_platform = "darwin" if platform.system() == "Darwin" else "linux"
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
            str(java_home / "include" / jni_platform),
            str(root / "ksu_timing_probe_test.cpp"),
            "-o",
            str(executable),
        ],
        check=True,
    )
    subprocess.run([str(executable)], check=True, timeout=10)
print(
    "Timing sampler ordering, per-CPU preflight, outcomes, bounded retries, UID, affinity and cleanup tests passed"
)
