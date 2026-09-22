# Release policy

Stable releases are built by `.github/workflows/release-latest.yml` from an existing `v*` tag.
Manual releases must start the workflow from the repository's default branch and name an existing
tag; the workflow never creates a tag from a branch head.

## Trusted source history

A stable release tag must point to a commit reachable from the repository's default branch. This
keeps tag-controlled Gradle and Android build logic inside the same reviewed history that is
allowed to receive the release signing credentials.

## Historical rebuild compatibility

Historical rebuilds are supported starting at commit
`641913a4efa743b200454b10b4d2e41ac02f1f39` (inclusive). That revision introduced the complete
`duckdetector.android.*` toolchain property contract consumed by the current shared Android setup
action. Tags on older commits are rejected rather than built with guessed modern SDK, build-tools,
CMake, or NDK versions.

The release workflow uses the workflow revision's shared setup action through the `$/` self-
repository reference while building source from the selected tag. The selected source tree still
supplies its own pinned toolchain values and Gradle build logic.
