#!/usr/bin/env python3
"""Verify the bounded production sampler using fake I/O; no real leak is triggered."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
import re
root = Path(__file__).resolve().parent
probe = root.parents[1] / "main/cpp/nativeroot/probes"
native = (probe / "ksu_wrapper_leak_probe.h").read_text().split("enum class WrapperStage {", 1)[1].split("}", 1)[0]
contract = (root.parents[3] / "domain/src/main/kotlin/com/eltavine/duckdetector/features/nativeroot/domain/KernelSuWrapperLeakObservation.kt").read_text()
contract = contract.split("enum class WrapperLeakCollection(val wireCode: Int) {", 1)[1].split("}", 1)[0]
native_codes = {re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper(): int(code)
                for name, code in re.findall(r"k(\w+)\s*=\s*(\d+)", native)}
kotlin_codes = {name: int(code) for name, code in re.findall(r"([A-Z_]+)\((-?\d+)\)", contract) if int(code) >= 0}
assert native_codes == kotlin_codes and len(native_codes) == 9, "Native/Kotlin wrapper status codes differ"
with tempfile.TemporaryDirectory(prefix="wrapper-leak-test-") as directory:
    output = Path(directory) / "test"
    subprocess.run([shutil.which("c++") or "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    "-I", str(probe), str(probe / "ksu_wrapper_leak_probe.cpp"),
                    str(root / "ksu_wrapper_leak_probe_test.cpp"), "-o", str(output)], check=True)
    subprocess.run([str(output)], check=True, timeout=10)
    # Darwin has statfs under sys/mount.h; the adapter itself targets Android/Linux.
    compatibility = Path(directory) / "sys"
    compatibility.mkdir()
    if sys.platform == "darwin":
        (compatibility / "vfs.h").write_text("#include <sys/mount.h>\n")
    subprocess.run([shutil.which("c++") or "c++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    "-I", directory, "-I", str(probe),
                    str(probe / "ksu_wrapper_leak_probe.cpp"), str(root / "ksu_wrapper_leak_posix_test.cpp"),
                    "-o", str(output)], check=True)
    subprocess.run([str(output)], check=True, timeout=10)
print("Wrapper sampler ordering, budget, counter parsing, failure paths and cleanup passed")
