#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run signal and loader regression fixtures against production path classification."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

OWNER = Path(__file__).resolve().parents[3]
ROOT = Path(__file__).resolve().parents[6]


class LoaderPathTest(unittest.TestCase):
    def test_signal_and_loader_evidence(self):
        compiler = shutil.which("c++")
        self.assertIsNotNone(compiler)
        cpp = OWNER / "src/main/cpp"
        with tempfile.TemporaryDirectory(prefix="memory-loader-path-") as directory:
            binary = Path(directory) / "test"
            subprocess.run([
                compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                "-I", str(OWNER / "src/test/native/include"), "-I", str(cpp),
                "-I", str(ROOT / "core/native/src/main/cpp"),
                str(cpp / "memory/common/maps_reader.cpp"),
                str(cpp / "memory/detectors/signal_detector.cpp"),
                str(cpp / "memory/detectors/linker_detector.cpp"),
                str(OWNER / "src/test/native/loader_path_test.cpp"), "-o", str(binary),
            ], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
