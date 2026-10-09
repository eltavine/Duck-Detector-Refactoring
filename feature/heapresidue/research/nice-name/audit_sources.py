#!/usr/bin/env python3
# Copyright (C) 2026 Duck Apps Contributor
# Licensed under the Apache License, Version 2.0.
"""Reproduce issue #363's source inputs, not its unvalidated device conclusions.

Only --fetch accesses the network. Cache files are decoded upstream source, never
device data. Hashes establish repeatable inputs; anchors locate code for review
and do not prove control flow, runtime reachability, or detector effectiveness.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 6 * 1024 * 1024
LOCK = Path(__file__).with_name("sources.json")


def verify_source(entry, data):
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("source exceeds size limit")
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("SHA-256 mismatch")
    lines = data.decode("utf-8").splitlines()
    locations = {}
    for anchor in entry["anchors"]:
        matches = [index + 1 for index, line in enumerate(lines) if anchor in line]
        if not matches:
            raise ValueError(f"missing source anchor: {anchor}")
        locations[anchor] = matches
    return locations


def validate_entry(entry):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", entry["id"]):
        raise ValueError("invalid cache identifier")
    revision = entry["revision"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("source revision must be a full commit ID")
    base = entry["repository"]
    if not re.fullmatch(
        r"https://(?:android\.googlesource\.com/[a-zA-Z0-9_/-]+"
        r"|github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+)", base
    ):
        raise ValueError("unexpected source repository")
    path = entry["path"]
    if not path or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError("invalid repository-relative source path")
    if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
        raise ValueError("invalid source hash")
    if not entry["anchors"] or not all(isinstance(a, str) and a for a in entry["anchors"]):
        raise ValueError("source anchors must be nonempty strings")


def fetch_source(entry):
    base, revision, path = entry["repository"], entry["revision"], entry["path"]
    if base.startswith("https://android.googlesource.com/"):
        url = f"{base}/+/{revision}/{path}?format=TEXT"
    else:
        repo = base.removeprefix("https://github.com/")
        url = f"https://raw.githubusercontent.com/{repo}/{revision}/{path}"
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError("download exceeds size limit")
    if base.startswith("https://android.googlesource.com/"):
        data = base64.b64decode(data, validate=True)
    return data


def audit(entries, cache, fetch=False):
    # Validate all paths before opening or writing any cache file.
    for entry in entries:
        validate_entry(entry)
    if len({entry["id"] for entry in entries}) != len(entries):
        raise ValueError("duplicate source identifier")
    if fetch:
        cache.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        destination = cache / (entry["id"] + ".source")
        data = fetch_source(entry) if fetch else destination.read_bytes()
        locations = verify_source(entry, data)
        if fetch:
            destination.write_bytes(data)
        yield {"id": entry["id"], "sha256": entry["sha256"], "anchor_lines": locations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true", help="download the pinned sources")
    args = parser.parse_args()
    try:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        if lock["schema"] != 1:
            raise ValueError("unsupported source lock schema")
        results = list(audit(lock["sources"], args.cache_dir, args.fetch))
    except (OSError, ValueError, KeyError) as error:
        print(f"Source audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"verified_sources": len(results), "sources": results}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
