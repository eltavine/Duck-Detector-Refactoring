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

"""Self-test for release_changes.py and release_manifest.py against a synthetic repository."""

from __future__ import annotations

import copy
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import release_changes  # noqa: E402
import release_manifest  # noqa: E402

REPOSITORY = "owner/repo"


class SyntheticRepository:
    def __init__(self, root: str) -> None:
        self.root = root
        self.git("init", "--quiet", "--initial-branch=main")

    def git(self, *arguments: str, author: str = "Main Author") -> str:
        environment = dict(
            os.environ,
            GIT_AUTHOR_NAME=author,
            GIT_AUTHOR_EMAIL="author@example.com",
            GIT_COMMITTER_NAME="Committer",
            GIT_COMMITTER_EMAIL="committer@example.com",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
        )
        return subprocess.run(
            ["git", "-C", self.root, *arguments],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        ).stdout.strip()

    def commit(self, subject: str, author: str = "Main Author", body: str | None = None) -> str:
        message = ["-m", subject] + (["-m", body] if body else [])
        self.git("commit", "--quiet", "--allow-empty", *message, author=author)
        return self.git("rev-parse", "HEAD")

    def merge_pull_request(self, number: int, title: str, author: str) -> str:
        self.git("checkout", "--quiet", "-b", f"topic-{number}")
        self.commit(f"wip for #{number}", author=author)
        self.commit(f"finish #{number}", author=author)
        self.git("checkout", "--quiet", "main")
        self.git(
            "merge", "--quiet", "--no-ff", f"topic-{number}",
            "-m", f"Merge pull request #{number} from someone/topic-{number}", "-m", title,
        )
        return self.git("rev-parse", "HEAD")


class ReleaseChangesTest(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.repo = SyntheticRepository(self._directory.name)
        self.repo.commit("feat: first commit")
        self.first_stable = self.repo.commit("fix: ready for stable (#3)", author="Squash Author")
        self.repo.git("tag", "v26.10.0")
        self.direct = self.repo.commit("docs: explain <channels> and *nightly*")
        self.merge = self.repo.merge_pull_request(7, "feat(update): add channels", author="Branch Author")
        self.squash = self.repo.commit("fix: keep the cache (#8)", author="Squash Author")

    def tearDown(self) -> None:
        self._directory.cleanup()

    def test_nearest_and_previous_stable_tags(self) -> None:
        self.assertEqual("v26.10.0", release_changes.nearest_stable_tag(self.repo.root, "HEAD"))
        self.assertEqual("v26.10.0", release_changes.nearest_stable_tag(self.repo.root, self.first_stable))
        self.assertIsNone(release_changes.previous_stable_tag(self.repo.root, "v26.10.0"))
        self.repo.git("tag", "v26.11.0")
        self.assertEqual("v26.10.0", release_changes.previous_stable_tag(self.repo.root, "v26.11.0"))

    def test_non_calendar_tags_are_not_stable_releases(self) -> None:
        self.repo.git("tag", "nightly")
        self.repo.git("tag", "v1.0")
        self.assertEqual("v26.10.0", release_changes.nearest_stable_tag(self.repo.root, "HEAD"))

    def test_changes_follow_the_first_parent_line(self) -> None:
        changes = release_changes.collect_changes(self.repo.root, "HEAD", "v26.10.0")

        self.assertEqual("v26.10.0", changes["baseTag"])
        self.assertEqual(self.first_stable, changes["baseSha"])
        self.assertEqual(3, changes["totalCount"])
        self.assertEqual([self.squash, self.merge, self.direct], [entry["sha"] for entry in changes["entries"]])
        squash, merge, direct = changes["entries"]
        self.assertEqual(("fix: keep the cache", 8, "Squash Author"),
                         (squash["subject"], squash["pullRequest"], squash["authorName"]))
        self.assertEqual(("feat(update): add channels", 7, "Branch Author"),
                         (merge["subject"], merge["pullRequest"], merge["authorName"]))
        self.assertIsNone(direct["pullRequest"])

    def test_changes_without_a_stable_tag_start_at_the_first_commit(self) -> None:
        changes = release_changes.collect_changes(self.repo.root, "HEAD", None, limit=2)

        self.assertIsNone(changes["baseTag"])
        self.assertIsNone(changes["baseSha"])
        self.assertEqual(5, changes["totalCount"])
        self.assertEqual(2, len(changes["entries"]))

    def test_nightly_note_links_changes_and_escapes_markdown(self) -> None:
        changes = release_changes.collect_changes(self.repo.root, "HEAD", "v26.10.0", limit=2)
        note = release_changes.render_nightly_note(changes, REPOSITORY, self.squash)

        self.assertIn("## Changes since [v26.10.0](https://github.com/owner/repo/releases/tag/v26.10.0)", note)
        self.assertIn("* fix: keep the cache by Squash Author in [#8](https://github.com/owner/repo/pull/8)", note)
        self.assertIn("1 earlier change is not listed.", note)
        self.assertIn(f"compare/v26.10.0...{self.squash}", note)
        full = release_changes.render_nightly_note(
            release_changes.collect_changes(self.repo.root, "HEAD", "v26.10.0"), REPOSITORY, self.squash
        )
        self.assertIn(r"docs: explain \<channels\> and \*nightly\*", full)
        self.assertIn(f"[`{self.direct[:8]}`](https://github.com/owner/repo/commit/{self.direct})", full)


class ReleaseManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.commit = {
            "sha": "a" * 40,
            "subject": "feat: ship it",
            "body": "",
            "authorName": "Duck",
            "authoredAt": "2026-10-01T08:00:00Z",
        }

    def manifest(self, channel: str, tag: str) -> dict:
        name = "Duck.Detector-26.10.0.apk"
        release = None
        if channel == "stable":
            release = {"tag": tag, "url": f"https://github.com/{REPOSITORY}/releases/tag/{tag}", "notes": "## What's Changed"}
        return release_manifest.build_manifest(
            channel=channel,
            branch="main",
            version_name="26.10.0",
            version_code=985,
            commit=self.commit,
            built_at="2026-10-01T08:30:00Z",
            apk={
                "name": name,
                "downloadUrl": f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}",
                "sizeBytes": 10,
                "sha256": "c" * 64,
            },
            release=release,
        )

    def test_valid_manifests_pass(self) -> None:
        release_manifest.validate_manifest(self.manifest("stable", "v26.10.0"), REPOSITORY)
        nightly = self.manifest("nightly", "nightly")
        nightly["changes"] = {
            "baseTag": "v26.10.0",
            "baseSha": "b" * 40,
            "totalCount": 1,
            "entries": [{"sha": "d" * 40, "subject": "fix: x", "authorName": "Duck", "pullRequest": 9}],
        }
        release_manifest.validate_manifest(nightly, REPOSITORY)

    def test_invalid_manifests_fail(self) -> None:
        stable = self.manifest("stable", "v26.10.0")
        cases = {
            "wrong version": lambda m: m.update(versionName="26.10.1"),
            "no release": lambda m: m.pop("release"),
            "other release url": lambda m: m["release"].update(url="https://example.com/"),
            "asset in another release": lambda m: m["apk"].update(
                downloadUrl=f"https://github.com/{REPOSITORY}/releases/download/v26.9.0/Duck.Detector-26.10.0.apk"),
            "proxy host": lambda m: m["apk"].update(downloadUrl="https://gh-proxy.com/https://github.com/x.apk"),
            "short sha": lambda m: m["commit"].update(sha="abc"),
            "bad digest": lambda m: m["apk"].update(sha256="xyz"),
            "unknown channel": lambda m: m.update(channel="beta"),
            "changes on stable": lambda m: m.update(changes={"baseTag": None, "baseSha": None, "totalCount": 0, "entries": []}),
        }
        for description, mutate in cases.items():
            candidate = copy.deepcopy(stable)
            mutate(candidate)
            with self.subTest(description), self.assertRaises(release_manifest.ManifestError):
                release_manifest.validate_manifest(candidate, REPOSITORY)

    def test_nightly_changes_are_validated(self) -> None:
        nightly = self.manifest("nightly", "nightly")
        nightly["changes"] = {"baseTag": "v26.10.0", "baseSha": None, "totalCount": 0, "entries": []}
        with self.assertRaises(release_manifest.ManifestError):
            release_manifest.validate_manifest(nightly, REPOSITORY)

    def test_apk_entry_hashes_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory, "Duck.Detector-26.10.0.apk")
            apk.write_bytes(b"duck")
            entry = release_manifest.apk_entry(apk, apk.name, "https://github.com/x")
        self.assertEqual(4, entry["sizeBytes"])
        self.assertEqual(hashlib.sha256(b"duck").hexdigest(), entry["sha256"])


if __name__ == "__main__":
    unittest.main()
