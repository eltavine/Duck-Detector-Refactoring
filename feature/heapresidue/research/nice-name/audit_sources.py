#!/usr/bin/env python3
# Copyright (C) 2026 Duck Apps Contributor
# Licensed under the Apache License, Version 2.0.
"""Reproduce issue #363's source inputs, not its unvalidated device conclusions.

Only --fetch accesses the network. The cache holds decoded upstream files and shallow Git
objects, never device data. Hashes and commit IDs make the inputs repeatable. Anchors locate
code for review; each search pins the exact file set behind one repository-wide statement.
None of this proves control flow, runtime reachability, or detector effectiveness.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 6 * 1024 * 1024
FETCH_ATTEMPTS = 3
GIT_TIMEOUT_SECONDS = 300
LOCK_SCHEMA = 2
LOCK = Path(__file__).with_name("sources.json")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]*")
REVISION = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REPOSITORY = re.compile(
    r"https://(?:android\.googlesource\.com/[a-zA-Z0-9_/-]+"
    r"|github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+)"
)
# Restricted so that a path can neither leave the repository nor change a fetch URL.
PATH_SEGMENT = re.compile(r"[A-Za-z0-9_.+-]+")


def text(entry, key, pattern=None):
    value = entry.get(key)
    if not isinstance(value, str) or not value or (pattern is not None and not pattern.fullmatch(value)):
        raise ValueError(f"invalid {key}: {value!r}")
    return value


def relative_path(value):
    if not isinstance(value, str) or not all(
        PATH_SEGMENT.fullmatch(part) and part not in (".", "..") for part in value.split("/")
    ):
        raise ValueError(f"invalid repository-relative path: {value!r}")
    return value


def validate_pin(entry):
    if not isinstance(entry, dict):
        raise ValueError("lock entries must be objects")
    text(entry, "id", IDENTIFIER)
    text(entry, "repository", REPOSITORY)
    text(entry, "revision", REVISION)


def validate_entry(entry):
    validate_pin(entry)
    relative_path(entry.get("path"))
    text(entry, "sha256", SHA256)
    anchors = entry.get("anchors")
    if not isinstance(anchors, list) or not anchors or not all(isinstance(a, str) and a for a in anchors):
        raise ValueError("source anchors must be a nonempty list of nonempty strings")


def validate_search(search):
    validate_pin(search)
    text(search, "claim")
    text(search, "pattern")
    expected = search.get("expected")
    if not isinstance(expected, list):
        raise ValueError("search expectations must be a list of paths")
    for path in expected:
        relative_path(path)
    if len(set(expected)) != len(expected):
        raise ValueError("duplicate search expectation")


def check_entries(entries, validate, kind):
    if not isinstance(entries, list):
        raise ValueError(f"{kind} entries must be a list")
    for entry in entries:
        validate(entry)
    if len({entry["id"] for entry in entries}) != len(entries):
        raise ValueError(f"duplicate {kind} identifier")


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


def download(url):
    # Retries absorb transient transport failures only; the pinned hash still decides acceptance.
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return response.read(MAX_DOWNLOAD_BYTES + 1)
        except urllib.error.HTTPError as error:
            if error.code < 500 or attempt == FETCH_ATTEMPTS:
                raise
        except OSError:
            if attempt == FETCH_ATTEMPTS:
                raise
        time.sleep(attempt)


def fetch_source(entry):
    base, revision, path = entry["repository"], entry["revision"], entry["path"]
    if base.startswith("https://android.googlesource.com/"):
        url = f"{base}/+/{revision}/{path}?format=TEXT"
    else:
        repo = base.removeprefix("https://github.com/")
        url = f"https://raw.githubusercontent.com/{repo}/{revision}/{path}"
    data = download(url)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError("download exceeds size limit")
    if base.startswith("https://android.googlesource.com/"):
        data = base64.b64decode(data, validate=True)
    return data


def audit(entries, cache, fetch=False):
    # Validate all paths before opening or writing any cache file.
    check_entries(entries, validate_entry, "source")
    if fetch:
        cache.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        destination = cache / (entry["id"] + ".source")
        data = fetch_source(entry) if fetch else destination.read_bytes()
        locations = verify_source(entry, data)
        if fetch:
            partial = destination.with_name(destination.name + ".partial")
            partial.write_bytes(data)
            partial.replace(destination)
        yield {"id": entry["id"], "sha256": entry["sha256"], "anchor_lines": locations}


def upstream_repository(cache):
    # Objects are content-addressed, so commits fetched from several remotes can share one store.
    return cache / "upstream.git"


def git(repository, *args):
    try:
        result = subprocess.run(["git", f"--git-dir={repository}", *args],
                                capture_output=True, timeout=GIT_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"git {args[0]} timed out") from error
    return result.returncode, result.stdout.decode("utf-8"), result.stderr.decode("utf-8", "replace").strip()


def fetch_revision(repository, remote, revision):
    if not repository.exists():
        repository.parent.mkdir(parents=True, exist_ok=True)
        status, _, error = git(repository, "init", "--quiet", "--bare")
        if status != 0:
            raise ValueError(f"cannot create upstream repository cache: {error}")
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        # A ref keeps the shallow commit reachable, so automatic garbage collection cannot drop it.
        status, _, error = git(repository, "fetch", "--quiet", "--depth=1", "--no-tags", remote,
                               f"{revision}:refs/audit/{revision}")
        if status == 0:
            return
        if attempt < FETCH_ATTEMPTS:
            time.sleep(attempt)
    raise ValueError(f"cannot fetch {remote} at {revision}: {error}")


def search_tree(search, repository):
    revision = search["revision"]
    status, output, _ = git(repository, "rev-parse", "--verify", "--quiet", revision + "^{commit}")
    if status != 0 or output.strip() != revision:
        raise ValueError(f"pinned commit for search {search['id']} is not cached")
    # The commit ID authenticates the whole tree, so the match set is reproducible offline.
    status, output, error = git(repository, "grep", "-z", "-l", "-I", "-E", "-e", search["pattern"], revision, "--")
    if status not in (0, 1):
        raise ValueError(f"search {search['id']} failed: {error}")
    found = sorted(name.removeprefix(revision + ":") for name in output.split("\0") if name)
    expected = sorted(search["expected"])
    if found != expected:
        raise ValueError(f"search {search['id']} matched {found}, expected {expected}")
    return found


def audit_searches(searches, cache, fetch=False):
    check_entries(searches, validate_search, "search")
    if not searches:
        return
    repository = upstream_repository(cache)
    if fetch:
        for remote, revision in sorted({(search["repository"], search["revision"]) for search in searches}):
            fetch_revision(repository, remote, revision)
    elif not repository.is_dir():
        raise ValueError("missing upstream repository cache; run with --fetch first")
    for search in searches:
        yield {"id": search["id"], "revision": search["revision"], "matches": search_tree(search, repository)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true", help="download the pinned sources and commits")
    args = parser.parse_args()
    try:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        if not isinstance(lock, dict) or lock.get("schema") != LOCK_SCHEMA:
            raise ValueError("unsupported source lock schema")
        sources, searches = lock.get("sources"), lock.get("searches")
        # Reject any malformed entry before the first network access or cache write.
        check_entries(sources, validate_entry, "source")
        check_entries(searches, validate_search, "search")
        results = list(audit(sources, args.cache_dir, args.fetch))
        search_results = list(audit_searches(searches, args.cache_dir, args.fetch))
    except (OSError, ValueError) as error:
        print(f"Source audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"verified_sources": len(results), "verified_searches": len(search_results),
                      "sources": results, "searches": search_results}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
