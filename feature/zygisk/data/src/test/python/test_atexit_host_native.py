#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise exit-handler evidence without relying on a host libc's private layout."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

OWNER = Path(__file__).resolve().parents[3]
ROOT = Path(__file__).resolve().parents[6]


class AtexitEvidenceTest(unittest.TestCase):
    def test_memory_copy_and_unreadable_pages(self):
        cpp = OWNER / "src/main/cpp"
        with tempfile.TemporaryDirectory(prefix="zygisk-atexit-memory-") as directory:
            binary = Path(directory) / "test"
            subprocess.run([
                shutil.which("c++"), "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-I", str(cpp),
                str(cpp / "zygisk/probes/atexit/self_memory.cpp"),
                str(OWNER / "src/test/native/atexit_self_memory_test.cpp"), "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)

    def test_runtime_anchors_and_visibility_limits(self):
        compiler = shutil.which("c++")
        self.assertIsNotNone(compiler)
        cpp = OWNER / "src/main/cpp"
        with tempfile.TemporaryDirectory(prefix="zygisk-atexit-") as directory:
            binary = Path(directory) / "test"
            subprocess.run([
                compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                "-I", str(cpp), "-I", str(ROOT / "core/native/src/main/cpp"),
                str(cpp / "zygisk/probes/atexit/table_evidence.cpp"),
                str(OWNER / "src/test/native/atexit_evidence_test.cpp"),
                "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)

    @unittest.skipUnless(Path("/usr/include/elf.h").exists(), "Host has no ELF headers; run this fixture with the Android NDK on an AVD")
    def test_private_elf_symbols_and_malformed_images(self):
        cpp = OWNER / "src/main/cpp"
        with tempfile.TemporaryDirectory(prefix="zygisk-atexit-elf-") as directory:
            binary = Path(directory) / "test"
            subprocess.run([
                shutil.which("c++"), "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-I", str(cpp),
                str(cpp / "zygisk/probes/atexit/libc_objects.cpp"),
                str(OWNER / "src/test/native/atexit_objects_test.cpp"), "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
