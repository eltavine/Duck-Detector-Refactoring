#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the shared startup/runtime mount ID policy against synthetic mount lists."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]


class MountIdObservationTest(unittest.TestCase):
    def test_mount_id_observations(self):
        compiler = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler, "A C++ compiler is required")
        with tempfile.TemporaryDirectory(prefix="mount-id-test-") as directory:
            binary = Path(directory) / "mount-id-observation-test"
            subprocess.run([
                compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                "-I", str(ROOT / "core/native/src/main/cpp"),
                str(ROOT / "core/native/src/test/cpp/mount_id_observation_test.cpp"),
                "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
