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

"""Build and validate update.json, the manifest the app reads for its update channel.

Both channels publish schema version 1. Stable adds the release it belongs to, whose notes are the
changelog, and Nightly adds the changes since the last stable release; clients released before either
field existed ignore them. validate_manifest applies the rules feature/update's UpdateManifestParser
enforces, so a manifest the workflow publishes is one the app accepts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
CHANNELS = ("nightly", "stable")
BRANCHES = ("main", "master")
NIGHTLY_TAG = "nightly"
STABLE_TAG_RE = re.compile(r"^v\d{2}\.(?:[1-9]|1[0-2])\.(?:0|[1-9]\d*)$")
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_ASSET_NAME_LENGTH = 255


class ManifestError(ValueError):
    pass


def iso8601(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def commit_entry(repo_root: str, revision: str) -> dict:
    def log(format_: str) -> str:
        return subprocess.run(
            ["git", "-C", repo_root, "log", "-1", f"--format={format_}", revision],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    return {
        "sha": log("%H"),
        "subject": log("%s"),
        "body": log("%b"),
        "authorName": log("%an"),
        "authoredAt": iso8601(int(log("%at"))),
    }


def apk_entry(path: Path, name: str, download_url: str) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "name": name,
        "downloadUrl": download_url,
        "sizeBytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def build_manifest(
    *,
    channel: str,
    branch: str,
    version_name: str,
    version_code: int,
    commit: dict,
    built_at: str,
    apk: dict,
    release: dict | None = None,
    changes: dict | None = None,
) -> dict:
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "channel": channel,
        "branch": branch,
        "versionName": version_name,
        "versionCode": version_code,
        "commit": commit,
        "builtAtUtc": built_at,
        "apk": apk,
    }
    if release is not None:
        manifest["release"] = release
    if changes is not None:
        manifest["changes"] = changes
    return manifest


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def _is_text(value: object) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _validate_changes(changes: object) -> None:
    _require(isinstance(changes, dict), "changes must be an object")
    base_tag, base_sha = changes.get("baseTag"), changes.get("baseSha")
    _require((base_tag is None) == (base_sha is None), "changes.baseTag and baseSha go together")
    _require(base_tag is None or (isinstance(base_tag, str) and STABLE_TAG_RE.match(base_tag)), "changes.baseTag")
    _require(base_sha is None or (isinstance(base_sha, str) and FULL_SHA_RE.match(base_sha)), "changes.baseSha")
    entries = changes.get("entries")
    _require(isinstance(entries, list), "changes.entries must be a list")
    total = changes.get("totalCount")
    _require(isinstance(total, int) and not isinstance(total, bool) and total >= len(entries), "changes.totalCount")
    for entry in entries:
        _require(isinstance(entry, dict), "changes entry must be an object")
        _require(isinstance(entry.get("sha"), str) and FULL_SHA_RE.match(entry["sha"]), "changes entry sha")
        _require(_is_text(entry.get("subject")), "changes entry subject")
        _require(isinstance(entry.get("authorName"), str), "changes entry authorName")
        pull_request = entry.get("pullRequest")
        _require(pull_request is None or _is_positive_int(pull_request), "changes entry pullRequest")


def validate_manifest(manifest: dict, repository: str) -> None:
    _require(manifest.get("schemaVersion") == SCHEMA_VERSION, "schemaVersion")
    channel = manifest.get("channel")
    _require(channel in CHANNELS, f"channel {channel!r}")
    _require(manifest.get("branch") in BRANCHES, "branch")
    _require(_is_text(manifest.get("versionName")), "versionName")
    _require(_is_positive_int(manifest.get("versionCode")), "versionCode")
    _require(isinstance(manifest.get("builtAtUtc"), str) and INSTANT_RE.match(manifest["builtAtUtc"]), "builtAtUtc")

    commit = manifest.get("commit")
    _require(isinstance(commit, dict), "commit")
    _require(isinstance(commit.get("sha"), str) and FULL_SHA_RE.match(commit["sha"]), "commit.sha")
    _require(_is_text(commit.get("subject")) and _is_text(commit.get("authorName")), "commit subject or author")
    _require(isinstance(commit.get("body", ""), str), "commit.body")
    _require(isinstance(commit.get("authoredAt"), str) and INSTANT_RE.match(commit["authoredAt"]), "commit.authoredAt")

    release = manifest.get("release")
    if channel == "stable":
        _require(isinstance(release, dict), "a stable manifest names its release")
        tag = release.get("tag")
        _require(isinstance(tag, str) and STABLE_TAG_RE.match(tag), f"release.tag {tag!r}")
        _require(manifest["versionName"] == tag[1:], "versionName must be the release tag without its v")
        _require(release.get("url") == f"https://github.com/{repository}/releases/tag/{tag}", "release.url")
        _require(isinstance(release.get("notes"), str), "release.notes")
        _require("changes" not in manifest, "a stable manifest carries release notes, not changes")
    else:
        tag = NIGHTLY_TAG
        _require(release is None, "a Nightly manifest names no release")
        if "changes" in manifest:
            _validate_changes(manifest["changes"])

    apk = manifest.get("apk")
    _require(isinstance(apk, dict), "apk")
    name = apk.get("name")
    _require(
        _is_text(name)
        and len(name) <= MAX_ASSET_NAME_LENGTH
        and name.lower().endswith(".apk")
        and not any(character in "/\\" or ord(character) < 32 for character in name),
        f"apk.name {name!r}",
    )
    _require(isinstance(apk.get("downloadUrl"), str), "apk.downloadUrl")
    url = urlsplit(apk["downloadUrl"])
    _require(
        url.scheme == "https" and url.netloc == "github.com" and url.query == "" and url.fragment == "",
        "apk.downloadUrl must be a plain github.com URL",
    )
    _require(url.path == f"/{repository}/releases/download/{tag}/{name}", "apk.downloadUrl is outside the release")
    _require(_is_positive_int(apk.get("sizeBytes")), "apk.sizeBytes")
    _require(isinstance(apk.get("sha256"), str) and SHA256_RE.match(apk["sha256"]), "apk.sha256")


def write_manifest(manifest: dict, repository: str, output: Path) -> None:
    validate_manifest(manifest, repository)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Write the stable channel's update.json.")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--repository", required=True, help="owner/name on GitHub")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--apk", required=True, type=Path, help="the APK exactly as it is uploaded")
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--built-at", required=True, help="build time as YYYY-MM-DDTHH:MM:SSZ")
    parser.add_argument("--notes", required=True, type=Path, help="the release notes in Markdown")
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args(argv)

    web = f"https://github.com/{arguments.repository}"
    manifest = build_manifest(
        channel="stable",
        branch="main",
        version_name=arguments.version_name,
        version_code=arguments.version_code,
        commit=commit_entry(arguments.repo_root, f"{arguments.tag}^{{commit}}"),
        built_at=arguments.built_at,
        apk=apk_entry(
            arguments.apk,
            arguments.apk.name,
            f"{web}/releases/download/{arguments.tag}/{arguments.apk.name}",
        ),
        release={
            "tag": arguments.tag,
            "url": f"{web}/releases/tag/{arguments.tag}",
            "notes": arguments.notes.read_text(encoding="utf-8"),
        },
    )
    try:
        write_manifest(manifest, arguments.repository, arguments.output)
    except ManifestError as error:
        print(f"update.json is invalid: {error}", file=sys.stderr)
        return 1
    print(f"Wrote {arguments.output} for {arguments.tag}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
