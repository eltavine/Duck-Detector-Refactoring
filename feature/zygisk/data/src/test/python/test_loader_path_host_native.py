#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify map/FD path evidence and count correlated observations once."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

OWNER = Path(__file__).resolve().parents[3]
ROOT = Path(__file__).resolve().parents[6]


class LoaderPathTest(unittest.TestCase):
    def test_map_fd_evidence(self):
        compiler = shutil.which("c++")
        self.assertIsNotNone(compiler)
        cpp = OWNER / "src/main/cpp"
        with tempfile.TemporaryDirectory(prefix="zygisk-loader-path-") as directory:
            binary = Path(directory) / "test"
            subprocess.run([
                compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                "-I", str(cpp), "-I", str(ROOT / "core/native/src/main/cpp"),
                str(cpp / "zygisk/probes/vmap_probe.cpp"),
                str(cpp / "zygisk/probes/fd_probe.cpp"),
                str(OWNER / "src/test/native/loader_path_test.cpp"), "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
