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

"""Fail when a source file reaches the repository's line limit.

A file that accumulates this many lines almost always owns several independent reasons
to change. The Kotlin coding conventions keep a file "not exceeding a few hundred lines"
(Source file organization), and the limit applies that to every source language here. It is
a review trigger for splitting along semantic ownership, not a target to pad or compress
towards.
"""

from __future__ import annotations

import argparse
import os
import sys

LINE_LIMIT = 400
SOURCE_SUFFIXES = (
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".S", ".s",
    ".java", ".kt", ".kts", ".gradle",
    ".py", ".sh",
)
SKIPPED_DIRECTORIES = {".git", ".gradle", ".idea", ".kotlin", ".cxx", "build", "node_modules", "__pycache__"}


def count_lines(path: str) -> int:
    with open(path, "rb") as handle:
        content = handle.read()
    if not content:
        return 0
    return content.count(b"\n") + (0 if content.endswith(b"\n") else 1)


def iter_source_files(repo_root: str):
    for directory, subdirectories, files in os.walk(repo_root):
        # A checked-out Git submodule (and any other nested worktree) owns its own source
        # policies. actions/checkout represents submodules with a `.git` file, so without
        # this boundary the parent repository accidentally audits vendored source too.
        if os.path.abspath(directory) != os.path.abspath(repo_root) and os.path.exists(os.path.join(directory, ".git")):
            subdirectories[:] = []
            continue
        subdirectories[:] = sorted(name for name in subdirectories if name not in SKIPPED_DIRECTORIES)
        for name in sorted(files):
            if name.endswith(SOURCE_SUFFIXES):
                path = os.path.join(directory, name)
                yield os.path.relpath(path, repo_root).replace(os.sep, "/"), path


def check(repo_root: str) -> list[str]:
    errors = []
    for relative, path in iter_source_files(repo_root):
        lines = count_lines(path)
        if lines >= LINE_LIMIT:
            errors.append(f"{relative} has {lines} lines; split it below {LINE_LIMIT} along semantic ownership")
    return errors


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    parser.add_argument("--repo-root", default=default_root)
    arguments = parser.parse_args(argv)
    errors = check(os.path.abspath(arguments.repo_root))
    if errors:
        for error in errors:
            print(f"source length violation: {error}", file=sys.stderr)
        return 1
    print(f"Every source file is below {LINE_LIMIT} lines.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
