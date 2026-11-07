# Release policy

Duck Detector publishes two channels, both built from `main` and signed with the same key:

| Channel | Workflow | Version name | Manifest the app reads |
| --- | --- | --- | --- |
| Stable | `release-latest.yml`, on a stable tag | `26.10.0` | `releases/latest/download/update.json` |
| Nightly | `build.yml`, on every push to `main` | `26.10.0-nightly.5+1a2b3c4d` | `releases/download/update/update.json` |

A Nightly version names the last stable release behind it and the number of first-parent commits
since; before the first stable tag, Nightly builds keep their dated `2026.09.30-<hash>` name. Both
channels set versionCode to 300 plus the commits behind the build, so a Stable and a Nightly build
of the same commit are the same version and either channel can update to the other. An app that
moves from Nightly to Stable is usually ahead of the latest Stable; Android does not install an
older versionCode over a newer one, so the app waits for the first Stable newer than itself instead
of offering a downgrade.

The app follows the channel its build was published on until the user picks one under Settings →
About → Update channel.

## Cutting a stable release

Stable tags are calendar versions: a two-digit year, the month without padding, and a patch number
that starts at 0 each month, as in `v26.10.0`, `v26.10.1` and `v26.11.0`.

1. Wait until `main` holds everything the release should contain and its CI is green.
2. Tag the head of `main` and push the tag:

   ```bash
   git fetch origin
   git tag -s v26.10.0 -m "Duck Detector 26.10.0" origin/main
   git push origin v26.10.0
   ```

3. The tag starts `release-latest.yml`, which:
   - builds the APK and SDK AAR with `-Pduckdetector.releaseTag`, which names the version after the
     tag and fails the build unless the tag points at the commit being built;
   - asks GitHub to generate the release notes from the previous stable tag, or from the start of the
     history for the first stable release, and uses them as the changelog;
   - writes `update.json`, which carries that changelog for the app, and `SHA256SUMS`, and has GitHub
     attest the build provenance of the APK and AAR;
   - creates a draft release with every asset, checks each asset's name, size and digest, and only
     then publishes the release as the latest one;
   - waits until `releases/latest/download/update.json` serves the new manifest, and posts the APK to
     the Telegram channel.

GitHub's release notes list merged pull requests. Commits pushed to `main` without a pull request do
not appear in them, so add anything important to the notes on GitHub after publishing. The app shows
the notes captured in `update.json` when the release was published.

A published stable release is final: its files are what users and `update.json` already refer to,
and the workflow refuses to rebuild it. Tag a new patch version to fix a release. A draft left behind
by a failed run is deleted and rebuilt when the workflow runs again for the same tag.

Manual releases must start the workflow from the repository's default branch and name an existing
stable tag; the workflow never creates a tag from a branch head.

## Nightly releases

Every push to `main` publishes a separate immutable Nightly archive and advances only the
JSON asset of the fixed `update` prerelease. The archive release note and the `changes` in its
`update.json` list the first-parent changes since the last stable tag, newest
first, so the app can tell what a newer Nightly adds to the build it runs without GitHub's compare
API, which gh-proxy.com cannot relay. `.github/scripts/release_changes.py` collects them and
`.github/scripts/release_manifest.py` writes and validates the manifest for both channels.

## Trusted source history

A stable release tag must point to a commit reachable from the repository's default branch. This
keeps tag-controlled Gradle and Android build logic inside the same reviewed history that is
allowed to receive the release signing credentials.

## Historical rebuild compatibility

Historical rebuilds are supported starting at commit
`641913a4efa743b200454b10b4d2e41ac02f1f39` (inclusive). That revision introduced the complete
`duckdetector.android.*` toolchain property contract consumed by the current shared Android setup
action. Tags on older commits are rejected rather than built with guessed modern SDK, build-tools,
CMake, or NDK versions. A stable tag must also be on a commit whose build logic reads
`duckdetector.releaseTag`; on older commits the build does not name the tag's version, and the
workflow stops before publishing.

The release workflow uses the workflow revision's shared setup action through the `$/` self-
repository reference, and the workflow revision's release scripts, while building source from the
selected tag. The selected source tree still supplies its own pinned toolchain values and Gradle
build logic.

## Release immutability

Keep the repository's **Release immutability** setting enabled. Stable releases and Nightly
archives must report `immutable: true` after publication; both workflows verify this state.
Published assets and tags are never replaced. Only the fixed `update` prerelease is mutable.
The stable workflow rejects the reserved literal `update` tag.

GitHub has no per-tag exclusion setting. The `update` entry must therefore be created once
by a repository administrator while the repository policy is disabled, before enabling it
again. Existing mutable releases remain mutable unless republished. Disabling the policy
does not unlock releases that are already immutable.

For this one-time setup:

1. Confirm that no publishing workflow is running, that the `update` name is unused, and
   that a complete, verified immutable archive is available.
2. Disable the repository policy using the documented repository API. Create a prerelease
   named `update`, targeting the current default-branch SHA, with exactly that archive's
   `update.json`. Set its title, notes, prerelease and latest metadata during this creation.
3. Confirm that the published entry reports `immutable: false` and contains only the JSON.
4. Restore and verify the repository policy in a `finally` block, including on failure.
5. Verify that the archive remains immutable and that asset-only replacement of the JSON
   preserves the fixed entry's ID, mutable state and tag target.

Never edit, unpublish, delete, recreate or republish the fixed release record after setup.
Never move its Git tag: it is a discovery address, not the source revision of the current APK.
Normal CI uses only Contents permissions; policy administration is excluded from CI.
The publisher rejects a missing, draft, locked or unexpected channel. It can repair a missing
JSON or a failed-upload `starter` asset after an interrupted replacement, but never creates the release itself.

References: [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
[existing-release behavior](https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/)
and [repository policy API](https://docs.github.com/en/rest/repos/repos).

## Nightly archives and the update channel

Each default-branch Nightly is archived under `nightly-yyyy-MM-dd-gitshortHash`, using the
build-start UTC date and the first eight hexadecimal characters of the full commit SHA.
The tag must resolve to that full commit. The APK, SDK AAR and schema-v1 `update.json` are
uploaded to a draft, verified, and only then published as a prerelease. A rerun on the same
date/commit reuses an existing complete immutable archive. Only unpublished drafts may be
removed and rebuilt; public archives are never deleted or overwritten.

GitHub may rotate temporary `untagged-*` draft browser URLs when the draft is edited.
Manifest URLs always use the final archive tag. Verification binds the release ID and
asset IDs returned by the uploads, enumerates assets with pagination, then downloads all
three through the asset-ID API to check their exact sizes and SHA-256 hashes. A missing
server digest never bypasses byte verification. Permanent browser URLs are checked only
after publication. The binary endpoint may stream or redirect; `gh api` handles transport.

The fixed `update` release contains exactly one asset, `update.json`. Its bytes are copied
unchanged from the verified public archive, so its APK and AAR URLs point directly to that
archive. No compatibility binaries are uploaded to the fixed entry. New clients discover
updates at `releases/download/update/update.json` and independently verify downloads against
the selected archive's official manifest, even if the discovery channel has since advanced.
The removed `nightly` endpoint is not restored: older app versions require one manual
upgrade from the release list. Android version support is unchanged.

The channel advances only after the archive and both binaries have been verified. An older
version/build time cannot roll it backwards. Replacing the JSON is the only channel write;
the release ID, metadata and Git ref stay unchanged. Rerunning an already current channel
performs no upload. The Telegram step uses the verified archived APK and sends only when
the channel advances.

`gh release upload --clobber` deletes the old asset before uploading its replacement. This
is not a transaction: a brief missing-manifest response is possible. If upload or readback
fails, the helper attempts to restore the previous JSON and reports failure. A failed
restoration can require a rerun; when no previous JSON survives, rollback ordering history
is unavailable. Clients retain their existing HTTP retries.

Offline regression fixtures run in CI as `test-nightly-release.py` and
`test-nightly-channel.py`. They include the workflow's manifest generator, rotating draft
URLs, ID mismatches, corrupt downloads, JSON-only channel writes and idempotent reruns.

API contracts: [releases](https://docs.github.com/en/rest/releases/releases),
[release assets](https://docs.github.com/en/rest/releases/assets) and
[CLI replacement semantics](https://cli.github.com/manual/gh_release_upload).
