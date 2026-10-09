# Copyright (C) 2026 Duck Apps Contributor
# Licensed under the Apache License, Version 2.0.
"""Checks that source reproducibility failures cannot pass as successful audits."""

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
        for field, value in [("id", "../outside"), ("revision", "main"),
                             ("path", "../test.java"), ("repository", "http://example.org")]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit.validate_entry(dict(self.entry, **{field: value}))

    def test_duplicate_identifiers_fail_before_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(audit, "fetch_source", side_effect=AssertionError("network")):
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    list(audit.audit([self.entry, self.entry], Path(directory), fetch=True))

    def test_failed_verification_does_not_overwrite_cached_source(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            source = cache / "test-source.source"
            source.write_bytes(self.data)
            with patch.object(audit, "fetch_source", return_value=b"incorrect response"):
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    list(audit.audit([self.entry], cache, fetch=True))
            self.assertEqual(self.data, source.read_bytes())


if __name__ == "__main__":
    unittest.main()
