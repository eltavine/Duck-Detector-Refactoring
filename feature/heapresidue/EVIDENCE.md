# Zygote heap residue evidence record

Status: reviewed

This experimental probe asks whether a newly bound isolated Android 16 process contains Java
String objects with complete startup arguments naming an exact policy target. A string's origin
cannot be authenticated from HPROF. Findings are low-confidence argument traces, not proof that
a target ran, remains installed, is genuine, or compromised the device. No outcome is all-clear.
The source mechanism is audited; cumulative history and device reproducibility are **not validated**.

## Signals

### Java startup argument residue in ART String objects

- Observable signal: complete `--package-name=`, `--nice-name=` and `--app-data-dir=` strings whose normalized package equals a target; only synthetic primitive arrays linked to a java.lang.String instance are eligible.
- Producing subsystem: framework zygote argument handling, ART heap inheritance and ART HPROF serialization.
- Mechanism: Java parsing obtains arguments with ZygoteCommandBuffer.nextArg and builds String objects; a child can inherit unreclaimed objects. Hprof::ProcessBody uses VisitObjectsPaused inside a GC critical section and ScopedSuspendAll. DumpHeapInstanceObject emits a synthetic byte or big-endian char value array immediately after its String instance. STRING records describe metadata, not arbitrary Java String values. A complete snapshot is not an authenticated record of startup events.
- References: frameworks/base ZygoteArguments.java#getInstance/parseArgs, ZygoteCommandBuffer.java#nextArg, ZygoteConnection.java#processCommand; art/runtime/hprof/hprof.cc#ProcessBody/DumpHeapInstanceObject/DumpHeap; pinned source links below.
- Applicability: runtime is restricted to API 36, the audited android16-security-release ART format; byte/char values and 4/8-byte identifiers are parsed. Source checks establish a possible mechanism, not availability on every OEM or runtime update. A later API requires its own audit.
- Visibility limits: native forkSimpleApps/nativeForkRepeatedly can avoid Java allocations; USAP reads arguments in a pool process, not necessarily the parent zygote. GC, ABI/zygote boundaries, modified runtimes, self-created or spoofed strings, process startup initialization and acquisition delay all affect coverage. No monotonicity or history-since-boot guarantee is established.
- Result states: observed (low-confidence exact target argument), not observed (complete snapshot with some syntactically usable startup arguments), inconclusive (no usable arguments, malformed records or byte limit), unavailable (binding/dump/transport/deadline failure), unsupported (other API), not evaluated (loading).
- Interpretation: exact target argument strings are one correlated signal family. A package may already be uninstalled or never have been genuine. No match means only that a target argument was not observed in this snapshot. Arbitrary byte arrays, metadata strings, embedded substrings and socket strings are excluded.

### Fresh isolated-process collection and GC timing diagnostics

- Observable signal: dump completion, age measured from Process.getStartUptimeMillis before hidden API setup, dump-call duration and pre-call art.gc.gc-count.
- Producing subsystem: ActivityManager isolated service creation, zygote/USAP startup, ART GC and VMDebug.
- Mechanism: bindIsolatedService assigns a unique instance per scan, without FLAG_USE_APP_ZYGOTE or zygotePreloadName. The child invokes only the hidden Debug.dumpHprofData(String, FileDescriptor) overload. A reliable pipe FD is passed over Binder; the host VM drains it while the child's Java threads are suspended. The child closes the writer and is killed on service destruction. Host nonblocking reads poll at most 250 ms between deadline/cancellation checks; closing the reader releases a pipe writer via EPIPE. Android 16 FdFile::Flush treats EINVAL from pipe fsync as success.
- References: developer.android.com reference/android/content/Context#bindIsolatedService, reference/android/os/Debug, reference/android/os/Process#getStartUptimeMillis; frameworks/base ProcessList.java#startProcess, ZygoteProcess.java#shouldAttemptUsapLaunch; art/runtime/gc/heap.cc#PreZygoteFork/PostForkChildAction, collector/concurrent_copying.cc#Sweep; art/libartbase/base/unix_file/fd_file.cc#Flush; system/sepolicy private/app.te, isolated_app_all.te and domain.te; kernel/common fs/pipe.c#pipe_write.
- Applicability: API 36 only. Service initialization and the host's Application/providers still execute before service binding; SDK hosts must keep their isolated-process initialization small. Main-zygote family routing does not establish that a process freshly forked at scan time: an eligible USAP may predate the scan. No architecture instructions or vendor-private interfaces are used.
- Visibility limits: collection is after onServiceConnected, not Service.onCreate or immediately at fork. Hidden API lookup can allocate or fail and is included in call duration. Age is not an exact fork-to-heap-freeze interval. GC count is diagnostic, not proof that non-moving residue survived. The collector's generation and a device-specific cutoff remain unknown. Binder, SELinux or OEM failure is explicitly unavailable, never negative.
- Result states: complete, hidden API unavailable, dump failed, reused process rejected, binding failed, timed out, malformed/limited stream, unsupported API.
- Interpretation: a complete dump establishes collection of this heap only. The implementation does not infer a full startup history, native fast-path participation, actual parent zygote identity, GC immunity or a universal two-second deadline from these diagnostics.

## Audited sources and corrections to issue #360

Audited 2026-10-09 against these immutable repository revisions:

| Repository / branch | Revision |
| --- | --- |
| frameworks/base / android16-security-release | `e96ce2b091188de3bf9cf6385e50a4559839d921` |
| art / android16-security-release | `ba2c65bbab5a55e204b32d7b1480011a1bcb57f9` |
| system/sepolicy / android16-security-release | `d4a7f392598cee96d9479a8ac0f84259c19b043a` |
| kernel/common / android16-6.12 | `e65d894191a4f781c98ca3fe40d147d058483419` |

- [ZygoteArguments](https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/com/android/internal/os/ZygoteArguments.java), [ZygoteCommandBuffer](https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/com/android/internal/os/ZygoteCommandBuffer.java), [ZygoteConnection](https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/com/android/internal/os/ZygoteConnection.java).
- [ProcessList](https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/services/core/java/com/android/server/am/ProcessList.java), [ZygoteProcess](https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/android/os/ZygoteProcess.java).
- [HiddenApiBypass 6.1 invoke](https://github.com/LSPosed/AndroidHiddenApiBypass/blob/v6.1/library/src/main/java/org/lsposed/hiddenapibypass/HiddenApiBypass.java) scans method signatures and invokes the matching method without calling the exemption-setting API; runtime compatibility still needs device validation.
- [Debug](https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/android/os/Debug.java) marks its FD overload `@hide`; the public API documents only the path overload. HiddenApiBypass invokes a single method in the isolated VM; no VM-wide exemptions are added.
- [HPROF](https://android.googlesource.com/platform/art/+/ba2c65bbab5a55e204b32d7b1480011a1bcb57f9/runtime/hprof/hprof.cc) suspends other managed threads through the entire write. A Java pipe reader in the same VM can deadlock. String contents live in synthetic primitive arrays, not the HPROF metadata STRING table.
- [FdFile](https://android.googlesource.com/platform/art/+/ba2c65bbab5a55e204b32d7b1480011a1bcb57f9/libartbase/base/unix_file/fd_file.cc) accepts EINVAL when flushing pipes; [VMDebug JNI](https://android.googlesource.com/platform/art/+/ba2c65bbab5a55e204b32d7b1480011a1bcb57f9/runtime/native/dalvik_system_VMDebug.cc) delegates the FD to HPROF without a debuggable/profileable gate.
- [String layout](https://android.googlesource.com/platform/art/+/ba2c65bbab5a55e204b32d7b1480011a1bcb57f9/runtime/mirror/string.h) and [heap visit order](https://android.googlesource.com/platform/art/+/ba2c65bbab5a55e204b32d7b1480011a1bcb57f9/runtime/gc/heap-visit-objects-inl.h) justify the bounded one-pass bootstrap and mandatory class-layout confirmation.
- [Heap](https://android.googlesource.com/platform/art/+/ba2c65bbab5a55e204b32d7b1480011a1bcb57f9/runtime/gc/heap.cc) only creates/collects zygote space on the first pre-fork. PostForkChildAction schedules footprint reductions and a CC task. Its task time is relative to `last_adj_time`, which can already include reductions: the issue's approximate 8–28 s range is not a general fork-relative upper bound. These scheduling values do not prove the actual GC deadline on a device.
- [ConcurrentCopying](https://android.googlesource.com/platform/art/+/ba2c65bbab5a55e204b32d7b1480011a1bcb57f9/runtime/gc/collector/concurrent_copying.cc) distinguishes immune image/zygote spaces and generational young-only sweeping. Source alone does not establish each inherited object's generation or survival.
- [isolated_app_all.te](https://android.googlesource.com/platform/system/sepolicy/+/d4a7f392598cee96d9479a8ac0f84259c19b043a/private/isolated_app_all.te) explicitly **allows** read/write of already-open app data files received over IPC while prohibiting opening them directly. This differs from the issue's stated FD limitation. [app.te](https://android.googlesource.com/platform/system/sepolicy/+/d4a7f392598cee96d9479a8ac0f84259c19b043a/private/app.te) permits appdomain FIFO communication. OEM/runtime access is still a device test, not inferred from reference policy.
- [ACK process memory inheritance](https://android.googlesource.com/kernel/common/+/e65d894191a4f781c98ca3fe40d147d058483419/kernel/fork.c) uses copy_mm/dup_mm; [copy_page_range](https://android.googlesource.com/kernel/common/+/e65d894191a4f781c98ca3fe40d147d058483419/mm/memory.c) write-protects COW mappings. This explains inherited heap pages without establishing how long Java objects remain uncollected.
- [ACK pipe_write](https://android.googlesource.com/kernel/common/+/e65d894191a4f781c98ca3fe40d147d058483419/fs/pipe.c) uses EPIPE/SIGPIPE when readers disappear. ACK is a semantics reference here, not a claim that every API 36 device ships 6.12.

## Algorithm and ownership

`feature/heapresidue/{domain,data,presentation,detector,ui}` owns all behavior. The only shared changes
are its catalog registration and the reviewed hidden-method gateway entry. It depends on no other
feature. Risk names are loaded only in the host after the dump request; the host's own package is
excluded. There is no network, package inventory, upload, raw-heap export or native module. Host byte/deadline limits do not bound ART's own native first-pass CPU/memory use. Unbind/onDestroy cleanup is best effort until the suspended VM resumes; device tests must verify eventual process exit, especially on cancellation.

The bounded streaming parser validates header, identifier width, unsigned lengths, record boundaries,
class metadata, String.value offsets, adjacent array object IDs and heap end. ART visits region and allocation-stack objects before bitmap objects, so a String instance may precede its class dump. The parser bootstraps offset 8 from the audited mirror::String count_/hash_code_ layout and requires the actual class metadata to confirm it before returning any result. A different layout is an explicit error. Unknown heap tags,
truncation, trailing bytes and over-budget records are errors. It skips irrelevant payloads in blocks
and decodes at most 1024 ASCII characters per eligible string. UTF-16 is read in HPROF big-endian order.
Package syntax, numeric user IDs, process suffixes and exact path endings are checked before exact
hash lookup. No benign package inventory or complete argument string is returned in a report.

For N input bytes and bounded candidate length L, I/O is O(N), matching is O(L) per candidate,
and auxiliary memory is bounded independently of heap size (64 KiB input buffer, 8 KiB skip buffer,
small metadata identifiers and at most one entry per policy target). IDs/offsets use primitive longs
so parsing does not box every object ID. KMP is useful for an unanchored single-pattern search, but
cannot establish object ownership or record boundaries. Aho–Corasick adds no value for three anchored
prefixes. Neither a raw substring search nor a whole-heap text conversion is used.

## Exact-name policy

Names are policy keys, never authenticated application identities. The initial list follows the
project's existing root-manager and dangerous-app exact-name policies, without importing their
implementation. Historical/alternate names deliberately remain keys and may no longer identify
current builds; renamed or repackaged apps are missed.

Primary examples inspected during this change:

- [Magisk Setup.kt, b268b361](https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/build-logic/src/main/java/Setup.kt): `com.topjohnwu.magisk`.
- [KernelSU manager build, df03912f](https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/build.gradle.kts): default `me.weishu.kernelsu`, overridable by build property.
- [APatch app build, 52600361](https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/build.gradle.kts): `me.bmax.apatch` namespace.
- [LSPosed root build, df74d83e](https://github.com/LSPosed/LSPosed/blob/df74d83eb03a44cc6ad268841ac2ada28d077c77/build.gradle.kts): `org.lsposed.manager` default manager package.
- [LSPatch root build, bbe8d93f](https://github.com/LSPosed/LSPatch/blob/bbe8d93fb9230f7b04babaf1c4a11642110f55a6/build.gradle.kts): `org.lsposed.lspatch` default manager package.

## Local retention

Only FLAG_DEBUGGABLE hosts enable the tee. Private `noBackupFilesDir/heap-residue` is excluded from
[Android Auto Backup](https://developer.android.com/identity/data/autobackup#Files). The store reserves room before writing, retains at most two completed dumps
and at most 64 MiB including the active spool, and caps each spool at 32 MiB. Captures are serialized
across this feature's SDK sessions. Crash leftovers are removed on the next debug capture. Exceeding
the spool budget or a storage error deletes the spool and continues detection; a typed retention
status is reported separately. Failed/cancelled captures are deleted. Raw files are never attached
to detector reports or exported/uploaded by this feature. An isolated heap is still sensitive:
SDK hosts may run Application/provider code in that process, so absence of business data is not
asserted. Release hosts never create a spool.

See [VALIDATION.md](VALIDATION.md) for the required device experiments before leaving Draft.
