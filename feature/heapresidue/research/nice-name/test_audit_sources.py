# Copyright (C) 2026 Duck Apps Contributor
# Licensed under the Apache License, Version 2.0.
"""Checks that source reproducibility failures cannot pass as successful audits."""

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import audit_sources as audit


class SourceAuditTest(unittest.TestCase):
    def setUp(self):
        self.data = b"first\nsource_symbol\nlast\n"
        self.entry = {
            "id": "test-source",
            "repository": "https://github.com/example/project",
            "revision": "a" * 40,
            "path": "src/test.java",
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "anchors": ["source_symbol"],
        }

    def test_offline_audit_has_no_network_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / "test-source.source").write_bytes(self.data)
            with patch.object(audit, "fetch_source", side_effect=AssertionError("network")):
                result = list(audit.audit([self.entry], cache))
            self.assertEqual({"source_symbol": [2]}, result[0]["anchor_lines"])

    def test_corrupt_source_and_missing_anchor_fail(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            audit.verify_source(self.entry, self.data + b"changed")
        with self.assertRaisesRegex(ValueError, "missing source anchor"):
            audit.verify_source(dict(self.entry, anchors=["absent"]), self.data)

    def test_missing_cache_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                list(audit.audit([self.entry], Path(directory)))

    def test_oversized_source_fails_before_hashing(self):
        with patch.object(audit, "MAX_SOURCE_BYTES", 2):
            with self.assertRaisesRegex(ValueError, "size limit"):
                audit.verify_source(self.entry, self.data)

    def test_invalid_lock_cannot_escape_cache_or_use_unpinned_sources(self):
        for field, value in [("id", "../outside"), ("revision", "main"), ("path", "../test.java"),
                             ("path", "src/test.java?format=JSON"), ("repository", "http://example.org"),
                             ("anchors", "source_symbol"), ("sha256", None)]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                audit.validate_entry(dict(self.entry, **{field: value}))

    def test_duplicate_identifiers_fail_before_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(audit, "fetch_source", side_effect=AssertionError("network")):
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    list(audit.audit([self.entry, self.entry], Path(directory), fetch=True))

    def test_only_transient_download_failures_are_retried(self):
        transient = [urllib.error.URLError("reset"), io.BytesIO(self.data)]
        with patch.object(audit.urllib.request, "urlopen", side_effect=transient) as urlopen, \
                patch.object(audit.time, "sleep"):
            self.assertEqual(self.data, audit.download("https://example.invalid/source"))
        self.assertEqual(2, urlopen.call_count)
        missing = urllib.error.HTTPError("https://example.invalid/source", 404, "Not Found", None, None)
        with patch.object(audit.urllib.request, "urlopen", side_effect=missing) as urlopen, \
                patch.object(audit.time, "sleep"), self.assertRaises(urllib.error.HTTPError):
            audit.download("https://example.invalid/source")
        self.assertEqual(1, urlopen.call_count)

    def test_main_verifies_another_lock_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "test-source.source").write_bytes(self.data)
            lock = root / "lock.json"
            lock.write_text(json.dumps({"schema": audit.LOCK_SCHEMA, "sources": [self.entry], "searches": []}))
            argv = ["audit_sources.py", "--lock", str(lock), "--cache-dir", str(root)]
            with patch.object(audit.sys, "argv", argv), patch("builtins.print"):
                self.assertEqual(0, audit.main())
            lock.write_text(json.dumps({"schema": 1, "sources": [], "searches": []}))
            with patch.object(audit.sys, "argv", argv), patch("builtins.print"):
                self.assertEqual(1, audit.main())

    def test_failed_verification_does_not_overwrite_cached_source(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            source = cache / "test-source.source"
            source.write_bytes(self.data)
            with patch.object(audit, "fetch_source", return_value=b"incorrect response"):
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    list(audit.audit([self.entry], cache, fetch=True))
            self.assertEqual(self.data, source.read_bytes())


def git(*args, cwd):
    # Isolated from user configuration such as commit signing or a default template.
    environment = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                       GIT_AUTHOR_NAME="audit", GIT_AUTHOR_EMAIL="audit@example.invalid",
                       GIT_COMMITTER_NAME="audit", GIT_COMMITTER_EMAIL="audit@example.invalid")
    result = subprocess.run(["git", *args], cwd=cwd, env=environment, check=True, capture_output=True, text=True)
    return result.stdout.strip()


class RepositorySearchTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        work = root / "work"
        (work / "app").mkdir(parents=True)
        (work / "app" / "Receiver.java").write_text('class Receiver { String process = ":magica_boot"; }\n')
        (work / "app" / "Other.java").write_text("class Other {}\n")
        git("init", "--quiet", cwd=work)
        git("add", "--all", cwd=work)
        git("commit", "--quiet", "--message", "fixture", cwd=work)
        self.revision = git("rev-parse", "HEAD", cwd=work)
        self.cache = root / "cache"
        git("clone", "--quiet", "--bare", str(work), str(audit.upstream_repository(self.cache)), cwd=root)
        self.search = {
            "id": "fixture-receiver",
            "repository": "https://github.com/example/project",
            "revision": self.revision,
            "claim": "Only the receiver names its process.",
            "pattern": r"magica_boot|setComponentEnabledSetting",
            "expected": ["app/Receiver.java"],
        }

    def tearDown(self):
        self.directory.cleanup()

    def run_offline(self, *searches, cache=None):
        with patch.object(audit, "fetch_revision", side_effect=AssertionError("network")):
            return list(audit.audit_searches(list(searches), cache or self.cache))

    def test_offline_search_reproduces_exact_match_set(self):
        self.assertEqual(["app/Receiver.java"], self.run_offline(self.search)[0]["matches"])
        absent = dict(self.search, id="fixture-absent", pattern="android:process", expected=[])
        self.assertEqual([], self.run_offline(absent)[0]["matches"])

    def test_extra_or_missing_match_fails(self):
        for expected in ([], ["app/Other.java", "app/Receiver.java"]):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, "matched"):
                self.run_offline(dict(self.search, expected=expected))

    def test_uncached_commit_or_repository_fails(self):
        with self.assertRaisesRegex(ValueError, "not cached"):
            self.run_offline(dict(self.search, revision="b" * 40))
        with self.assertRaisesRegex(ValueError, "missing upstream"):
            self.run_offline(self.search, cache=self.cache / "absent")

    def test_invalid_search_fails_before_fetch(self):
        for field, value in [("expected", ["../outside"]), ("expected", "app/Receiver.java"),
                             ("expected", ["app/Receiver.java", "app/Receiver.java"]),
                             ("revision", "main"), ("pattern", ""), ("claim", None)]:
            with self.subTest(field=field, value=value):
                with patch.object(audit, "fetch_revision", side_effect=AssertionError("network")):
                    with self.assertRaises(ValueError):
                        list(audit.audit_searches([dict(self.search, **{field: value})], self.cache, fetch=True))


if __name__ == "__main__":
    unittest.main()
