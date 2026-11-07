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

"""Collect the changes a build carries since the last stable release and render the Nightly note.

Every Nightly build is made from a commit on main's first-parent line, so that line lists each change
once: a squashed or direct commit, or the merge of a pull request, named by the pull request title
GitHub writes as the first line of the merge message. The app finds the build it runs in this list,
so the list, rather than GitHub's compare API, tells it what a newer build adds.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

STABLE_TAG_GLOB = "v[0-9][0-9].[0-9]*"
STABLE_TAG_RE = re.compile(r"^v\d{2}\.(?:[1-9]|1[0-2])\.(?:0|[1-9]\d*)$")
MERGE_PULL_REQUEST_RE = re.compile(r"^Merge pull request #(\d+) from ")
SQUASHED_PULL_REQUEST_RE = re.compile(r"\s*\(#(\d+)\)$")
DEFAULT_LIMIT = 100
FIELD_SEPARATOR = "\x1f"
RECORD_SEPARATOR = "\x1e"
MARKDOWN_SPECIAL = re.compile(r"([\\`*_\[\]<>|])")


def git(repo_root: str, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", repo_root, *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def is_stable_tag(tag: str) -> bool:
    return STABLE_TAG_RE.match(tag) is not None


def nearest_stable_tag(repo_root: str, revision: str) -> str | None:
    """The newest stable tag reachable from revision, which counts itself when it is tagged."""
    result = subprocess.run(
        ["git", "-C", repo_root, "describe", "--tags", "--abbrev=0", "--match", STABLE_TAG_GLOB, revision],
        capture_output=True,
        text=True,
    )
    tag = result.stdout.strip()
    if result.returncode != 0 or not is_stable_tag(tag):
        return None
    return tag


def previous_stable_tag(repo_root: str, tag: str) -> str | None:
    """The stable tag before tag: the nearest one reachable from the tagged commit's first parent."""
    parent = subprocess.run(
        ["git", "-C", repo_root, "rev-parse", "--verify", "--quiet", f"{tag}^{{commit}}^"],
        capture_output=True,
        text=True,
    )
    if parent.returncode != 0:
        return None
    return nearest_stable_tag(repo_root, parent.stdout.strip())


def _entry(repo_root: str, record: str) -> dict:
    sha, parents, author, subject, body = record.split(FIELD_SEPARATOR, 4)
    pull_request = None
    merge = MERGE_PULL_REQUEST_RE.match(subject)
    if len(parents.split()) > 1 and merge:
        pull_request = int(merge.group(1))
        title = next((line.strip() for line in body.splitlines() if line.strip()), "")
        subject = title or subject
        # The merge commit's author merged the pull request; its branch tip names who wrote it.
        author = git(repo_root, "log", "-1", "--format=%an", f"{sha}^2").strip() or author
    else:
        squashed = SQUASHED_PULL_REQUEST_RE.search(subject)
        if squashed:
            pull_request = int(squashed.group(1))
            subject = subject[: squashed.start()]
    return {
        "sha": sha,
        "subject": subject.strip() or sha[:8],
        "authorName": author.strip(),
        "pullRequest": pull_request,
    }


def collect_changes(repo_root: str, head: str, base_tag: str | None, limit: int = DEFAULT_LIMIT) -> dict:
    """First-parent changes after base_tag up to head, newest first, at most limit of them."""
    head_sha = git(repo_root, "rev-parse", "--verify", f"{head}^{{commit}}").strip()
    base_sha = None
    revision_range = head_sha
    if base_tag is not None:
        base_sha = git(repo_root, "rev-parse", "--verify", f"{base_tag}^{{commit}}").strip()
        revision_range = f"{base_sha}..{head_sha}"
    total = int(git(repo_root, "rev-list", "--first-parent", "--count", revision_range).strip())
    log = git(
        repo_root,
        "log",
        "--first-parent",
        f"--max-count={limit}",
        f"--format=%H{FIELD_SEPARATOR}%P{FIELD_SEPARATOR}%an{FIELD_SEPARATOR}%s{FIELD_SEPARATOR}%b{RECORD_SEPARATOR}",
        revision_range,
    )
    records = [record.strip("\n") for record in log.split(RECORD_SEPARATOR)]
    entries = [_entry(repo_root, record) for record in records if record]
    return {
        "baseTag": base_tag,
        "baseSha": base_sha,
        "totalCount": total,
        "entries": entries,
    }


def escape_markdown(text: str) -> str:
    return MARKDOWN_SPECIAL.sub(r"\\\1", text)


def render_nightly_note(changes: dict, repository: str, head_sha: str) -> str:
    web = f"https://github.com/{repository}"
    base_tag = changes["baseTag"]
    lines = [f"Nightly build of `main` at [`{head_sha[:8]}`]({web}/commit/{head_sha}).", ""]
    if base_tag is None:
        lines.append("## Recent changes")
    else:
        lines.append(f"## Changes since [{base_tag}]({web}/releases/tag/{base_tag})")
    lines.append("")
    entries = changes["entries"]
    if not entries:
        lines.append(f"No changes since {base_tag}." if base_tag else "No changes.")
    for entry in entries:
        if entry["pullRequest"] is not None:
            link = f"[#{entry['pullRequest']}]({web}/pull/{entry['pullRequest']})"
        else:
            link = f"[`{entry['sha'][:8]}`]({web}/commit/{entry['sha']})"
        lines.append(f"* {escape_markdown(entry['subject'])} by {escape_markdown(entry['authorName'])} in {link}")
    hidden = changes["totalCount"] - len(entries)
    if hidden > 0:
        lines.extend(["", f"{hidden} earlier {'change is' if hidden == 1 else 'changes are'} not listed."])
    compare = f"{web}/compare/{base_tag}...{head_sha}" if base_tag else f"{web}/commits/{head_sha}"
    lines.extend(["", f"**Full Changelog**: {compare}", ""])
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--repository", required=True, help="owner/name on GitHub")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--changes-output", required=True, help="where to write the changes JSON")
    parser.add_argument("--note-output", required=True, help="where to write the Nightly release note")
    arguments = parser.parse_args(argv)

    head_sha = git(arguments.repo_root, "rev-parse", "--verify", f"{arguments.head}^{{commit}}").strip()
    base_tag = nearest_stable_tag(arguments.repo_root, head_sha)
    changes = collect_changes(arguments.repo_root, head_sha, base_tag, arguments.limit)
    with open(arguments.changes_output, "w", encoding="utf-8") as handle:
        json.dump(changes, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    with open(arguments.note_output, "w", encoding="utf-8") as handle:
        handle.write(render_nightly_note(changes, arguments.repository, head_sha))
    print(f"{len(changes['entries'])} of {changes['totalCount']} changes since {base_tag or 'the first commit'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
