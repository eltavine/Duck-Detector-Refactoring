#!/usr/bin/env python3
# Copyright (C) 2026 Duck Apps Contributor
# If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Self-test for check-source-file-length.py using synthetic source trees."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

CHECKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-source-file-length.py")
LIMIT = 400


class SourceFileLengthCheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.root = self._directory.name

    def tearDown(self) -> None:
        self._directory.cleanup()

    def write_lines(self, relative_path: str, count: int, trailing_newline: bool = True) -> None:
        path = os.path.join(self.root, relative_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        body = "\n".join(f"line {index}" for index in range(count))
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body + ("\n" if trailing_newline and count else ""))

    def run_checker(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, CHECKER, "--repo-root", self.root],
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_rejected(self, expected_message: str) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn(expected_message, result.stderr)

    def test_accepts_files_below_the_limit(self) -> None:
        self.write_lines("app/src/main/java/Small.kt", LIMIT - 1)
        self.write_lines("app/src/main/cpp/small.cpp", LIMIT - 1, trailing_newline=False)
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_file_at_the_limit(self) -> None:
        self.write_lines("app/src/main/java/Large.kt", LIMIT)
        self.assert_rejected(f"app/src/main/java/Large.kt has {LIMIT} lines")

    def test_counts_final_line_without_newline(self) -> None:
        self.write_lines("app/src/main/cpp/large.cpp", LIMIT, trailing_newline=False)
        self.assert_rejected(f"large.cpp has {LIMIT} lines")

    def test_covers_build_scripts_and_tooling(self) -> None:
        for path in ("build.gradle.kts", "tools/check.py", "tools/run.sh", "lib/probe.S", "lib/probe.h"):
            self.write_lines(path, LIMIT)
        result = self.run_checker()
        self.assertEqual(result.returncode, 1)
        for path in ("build.gradle.kts", "tools/check.py", "tools/run.sh", "lib/probe.S", "lib/probe.h"):
            self.assertIn(path, result.stderr)

    def test_ignores_non_source_and_build_outputs(self) -> None:
        self.write_lines("app/src/main/res/values/strings.xml", LIMIT * 2)
        self.write_lines("docs/architecture.md", LIMIT * 2)
        self.write_lines("app/build/generated/Huge.kt", LIMIT * 2)
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ignores_checked_out_submodule_sources(self) -> None:
        self.write_lines("uihelper/src/main/kotlin/Huge.kt", LIMIT * 2)
        with open(os.path.join(self.root, "uihelper", ".git"), "w", encoding="utf-8") as handle:
            handle.write("gitdir: ../.git/modules/uihelper\n")
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reports_every_violation(self) -> None:
        self.write_lines("feature/a/src/main/kotlin/A.kt", LIMIT)
        self.write_lines("feature/b/src/main/kotlin/B.kt", LIMIT + 50)
        result = self.run_checker()
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"A.kt has {LIMIT} lines", result.stderr)
        self.assertIn(f"B.kt has {LIMIT + 50} lines", result.stderr)

    def test_a_leftover_baseline_file_grants_no_exemption(self) -> None:
        self.write_lines("app/src/main/java/Legacy.kt", 700)
        policy = os.path.join(self.root, ".github", "policies", "source-file-length-baseline.json")
        os.makedirs(os.path.dirname(policy))
        with open(policy, "w", encoding="utf-8") as handle:
            json.dump({"schema_version": 1, "files": {"app/src/main/java/Legacy.kt": 700}}, handle)
        self.assert_rejected("Legacy.kt has 700 lines")


if __name__ == "__main__":
    unittest.main(verbosity=2)
