# Heap residue: Android release support audit

Research date: 2026-10-10. Question: do the collector and parser assumptions audited for
Android 16 hold for Android 12, 12L, 13, 14, 15 and 17? Scope: each release's security-release
branch, compared with the Android 16 baseline in [EVIDENCE.md](../../EVIDENCE.md). Device
validation is pending for every release, including Android 16.

## Decision

- Run the probe on API 31–37 and report them as audited baselines.
- Run it on releases newer than API 37 but report them as unaudited. Only the runtime checks
  protect those releases: a format change that breaks parsing yields inconclusive, a changed dump
  path or policy yields unavailable, and absent argument strings yield inconclusive rather than
  "not observed".
- Keep API 29–30 unsupported; they were not audited.
- Replace `Parcel.enforceNoDataAvail()` (API 33) with the same check on `dataAvail()`, and annotate
  the collector for API 31, the probe's minimum, because `Os.fcntlInt` is public only from API 30.

## Inputs and reproducibility

| Release (API) | frameworks/base | art | libcore | system/sepolicy |
| --- | --- | --- | --- | --- |
| 12 (31) | `25d54573` | `7b487412` | `7a9b98f8` | `27dbd800` |
| 12L (32) | `a5fbddcb` | `ab1f62ad` | `0c0acdd1` | `86c56a47` |
| 13 (33) | `d5622d9e` | `4bf98aff` | `e0b6b233` | `9d7c07e5` |
| 14 (34) | `06c9632b` | `f9801ba4` | `b818b182` | `d923a9c7` |
| 15 (35) | `d10ab1bb` | `83b3910c` | `c712224c` | `ad1c4255` |
| 16 (36), baseline | `e96ce2b0` | `ba2c65bb` | `fff4fcc0` | `d4a7f392` |
| 17 (37) | `48fe68e0` | `ecd0dfa4` | `4ebfb391` | `895c7f4d` |

These are the `android1x-security-release` heads read on 2026-10-10 (Android 17:
`android17-security-release`); `sources.json` records the full commit IDs and pins 91 files with
SHA-256 and anchors, 13 per release. From the repository root:

```sh
python3 feature/heapresidue/research/nice-name/audit_sources.py --lock feature/heapresidue/research/version-support/sources.json --fetch --cache-dir /tmp/duck-heap-releases
python3 feature/heapresidue/research/nice-name/audit_sources.py --lock feature/heapresidue/research/version-support/sources.json --cache-dir /tmp/duck-heap-releases
```

The first command downloads public source; the second is offline. Anchors locate the reviewed
code. They do not prove control flow, OEM behavior or device results.

## Findings

Each finding holds for all seven releases unless a release is named.

1. **HPROF String encoding** (`hprof-*`). The writer emits the magic `JAVA PROFILE 1.0.3` and
   4-byte identifiers. It writes a String's real instance fields, appends a synthetic `value`
   object field, and follows the instance with a primitive array dump of the same ID, holding
   bytes for compressed strings and chars otherwise. `hprof.cc` is byte-identical from 12 to 14.
   14 to 15 changes only annotations; 15 to 16 refactors field iteration with the same output.
   17 adds `HPROF_TAG_ART_CLOCK_MONOTONIC` (`0xA0`, one U8) as a top-level record right after the
   fixed header, which the parser skips by length (fixture-tested), and refactors the zygote
   large-object check without changing the records written.
2. **String layout** (`string-*`). `mirror::String` declares `int32_t count_` and
   `uint32_t hash_code_` before its value in every release, so the synthetic `value` sits at
   offset 8. The parser still confirms that offset against the actual class dump.
3. **Dump path** (`debug-*`, `vmdebug-*`, `vmdebug-jni-*`). The hidden
   `Debug.dumpHprofData(String, FileDescriptor)` delegates to libcore `VMDebug`, which passes the
   raw FD to `VMDebug_dumpHprofData`. That function calls `hprof::DumpHeap(filename, fd, false)`
   with no debuggable or profileable gate.
4. **Pipe flush** (`fd-file-*`). `FdFile::Flush` returns success when `fdatasync`/`fsync` fails
   with `EINVAL`, as it does on a pipe.
5. **Transport policy** (`app-*`, `te-macros-*`, `mls-*`, `fs-use-*`, `isolated-app-*`).
   `binder_call(appdomain, appdomain)` grants `fd use`, and appdomain-to-appdomain rules grant
   `fifo_file` read/write and `unix_stream_socket { getopt getattr read write shutdown }`.
   `app_domain(isolated_app)` puts the collector in appdomain. `fs_use_task pipefs` and `sockfs`
   label the pipe and the reliable pipe's socketpair with the host app's domain. MLS lets a
   `fifo_file` be read or written whenever the object type is a domain (`t2 == domain`), and it
   constrains sockets only on create, relabel and `connectto`, not on reading or writing an
   existing `unix_stream_socket`. Android 17 excludes only `pcc_component`
   from the two app rules. From Android 14 the `:isolatedComputeApp` seinfo applies only to
   specific system service actions, so this explicit-component service stays `isolated_app`.
6. **Collector routing** (`active-services-*`, `zygote-process-*`). Service launches request
   `ZYGOTE_POLICY_FLAG_EMPTY`. Android 17 adds `ZYGOTE_POLICY_FLAG_NATIVE_PROCESS` only for native
   isolated services behind a prototype flag. `policySpecifiesUsapPoolLaunch` is unchanged, so the
   platform zygote forks the collector on request rather than handing over a pooled USAP.

Outside AOSP: [HiddenApiBypass 6.1](https://github.com/LSPosed/AndroidHiddenApiBypass/blob/v6.1/README.md),
the latest tag, declares support through Android 16. On Android 17 a failure stays inside the
isolated process: an exception is reported as the hidden API stage, a crash as a failed dump.

## What this does not establish

- API level identifies the platform release, not the ART module. ART updates through Mainline,
  so a device may run a newer ART than its release. Every audited ART revision shares the
  behavior above, which covers modules in that range. A module newer than Android 17 is covered
  only by the runtime checks.
- OEM ART or sepolicy changes, kernel behavior, and per-release differences in GC timing,
  zygote routing of other apps' launches or observable history. These affect coverage, never the
  meaning of a match; [VALIDATION.md](../../VALIDATION.md) lists the device experiments.
- Any device result. No device was connected for this audit.
