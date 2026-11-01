#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify Android installation-token parsing without changing file identity."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]


class InstalledPackagePathTest(unittest.TestCase):
    def test_installation_paths(self):
        compiler = shutil.which("c++")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="installed-package-path-") as directory:
            binary = Path(directory) / "test"
            subprocess.run([
                compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                "-I", str(ROOT / "core/native/src/main/cpp"),
                str(ROOT / "core/native/src/test/cpp/installed_package_path_test.cpp"),
                "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
