# Experimental fsnotify SRCU timing

This diagnostic asks whether a synchronous package-settings stimulus repeatedly coincides with elevated inotify close latency. It reports global fsnotify/SRCU contention as supporting evidence, without identifying a reader or root solution. It is disabled until the user explicitly enables it.

## Verified source chain

The relevant subsystem is kernel fsnotify mark destruction, not reads of another application's package directory. The sampler watches an empty directory in its own cache, then times closing the entire inotify instance. Removing a watch alone is not the measured operation.

ACK `fs/notify/inotify/inotify_user.c:inotify_release` calls `fsnotify_destroy_group`. `fs/notify/group.c` waits for mark destruction; `fs/notify/mark.c` flushes the global mark reaper, which calls `synchronize_srcu(&fsnotify_mark_srcu)`. `fs/notify/fsnotify.c` uses this SRCU domain around dispatch to notification handlers. SRCU waits for relevant pre-existing readers; it does not reveal their identities. `fs/file_table.c:fput` may defer file release through task_work before returning to user space, so the full `close` call includes that release path.

The mark/group path was checked in these exact ACK revisions:

| Family / reviewed branch | Revision and source |
| --- | --- |
| 5.10 / android12-5.10 | [ba7e98f3, mark.c](https://android.googlesource.com/kernel/common/+/ba7e98f3605e140fe13a76e5068409cfdc68da4f/fs/notify/mark.c), [group.c](https://android.googlesource.com/kernel/common/+/ba7e98f3605e140fe13a76e5068409cfdc68da4f/fs/notify/group.c) |
| 5.15 / android14-5.15 | [76efa001, mark.c](https://android.googlesource.com/kernel/common/+/76efa001ea197723c0423fdb9136e83b483f7aa1/fs/notify/mark.c), [group.c](https://android.googlesource.com/kernel/common/+/76efa001ea197723c0423fdb9136e83b483f7aa1/fs/notify/group.c) |
| 6.1 / android14-6.1 | [3b088464, mark.c](https://android.googlesource.com/kernel/common/+/3b0884642a507e556489aec2ff359379fe44c9d2/fs/notify/mark.c), [group.c](https://android.googlesource.com/kernel/common/+/3b0884642a507e556489aec2ff359379fe44c9d2/fs/notify/group.c) |
| 6.6 / android15-6.6 | [78302535, mark.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/fs/notify/mark.c), [group.c](https://android.googlesource.com/kernel/common/+/783025351c5fb3bcb4591d8fc61cbbd709aa4bcf/fs/notify/group.c) |
| 6.12 / android16-6.12 | [c47ebb74, mark.c](https://android.googlesource.com/kernel/common/+/c47ebb7427d5011de67b526eac67b42da640bdc5/fs/notify/mark.c), [group.c](https://android.googlesource.com/kernel/common/+/c47ebb7427d5011de67b526eac67b42da640bdc5/fs/notify/group.c) |

The complete dispatch and release chain was checked in the 6.12 revision: [inotify_user.c](https://android.googlesource.com/kernel/common/+/c47ebb7427d5011de67b526eac67b42da640bdc5/fs/notify/inotify/inotify_user.c), [fsnotify.c](https://android.googlesource.com/kernel/common/+/c47ebb7427d5011de67b526eac67b42da640bdc5/fs/notify/fsnotify.c), [file_table.c](https://android.googlesource.com/kernel/common/+/c47ebb7427d5011de67b526eac67b42da640bdc5/fs/file_table.c), [SRCU documentation](https://android.googlesource.com/kernel/common/+/c47ebb7427d5011de67b526eac67b42da640bdc5/Documentation/RCU/whatisRCU.rst).

The public stimulus is [PackageManager.addPermission](https://developer.android.com/reference/android/content/pm/PackageManager#addPermission(android.content.pm.PermissionInfo)), with `nonLocalizedLabel` alternating under the host's own permission tree. Its synchronous form passes `async=false`; `false` as its return value also means an existing permission was changed. The implementation therefore checks the label afterward instead of treating `false` as failure.

- Android 11 (excluded): [PermissionManagerService.java](https://android.googlesource.com/platform/frameworks/base/+/android-11.0.0_r1/services/core/java/com/android/server/pm/permission/PermissionManagerService.java) reaches the same `addPermission` and `writeSettings` path, but [BasePermission.java](https://android.googlesource.com/platform/frameworks/base/+/android-11.0.0_r48/services/core/java/com/android/server/pm/permission/BasePermission.java) `addToTree` stores a copy of the tree's `ParsedPermission` instead of the supplied info, from r1 through r48. `getPermissionInfo` then returns the tree's name and label, so the readback can never confirm a change.
- Android 12: [PermissionManagerService.java](https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/services/core/java/com/android/server/pm/permission/PermissionManagerService.java), same synchronous settings path; [Permission.java](https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/services/core/java/com/android/server/pm/permission/Permission.java) `addToTree` stores the supplied `PermissionInfo`, so the label readback holds from here on.
- Android 13: [PermissionManagerServiceImpl.java](https://android.googlesource.com/platform/frameworks/base/+/android-13.0.0_r1/services/core/java/com/android/server/pm/permission/PermissionManagerServiceImpl.java).
- Android 14: [PermissionManagerServiceImpl.java](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/services/core/java/com/android/server/pm/permission/PermissionManagerServiceImpl.java); [Settings.java](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/services/core/java/com/android/server/pm/Settings.java) writes packages.list with settings. Permission trees are stored separately from permissions: `getPermissionInfo(tree)` cannot verify a tree. `addPermission` enforces tree ownership in system_server.
- Android 15: [PermissionManager.java](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/core/java/android/permission/PermissionManager.java) selects AccessCheckingService from V; [PermissionService.kt](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/services/permission/java/com/android/server/permission/access/permission/PermissionService.kt) changes access state instead of using the legacy settings path.
- Android 16: [AccessCheckingService.kt](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/permission/java/com/android/server/permission/access/AccessCheckingService.kt) and [AccessPersistence.kt](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/permission/java/com/android/server/permission/access/AccessPersistence.kt) persist `access.abx`. Android 15+ is excluded even if an OEM might retain a legacy backend.

[Bionic's syscall declarations](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r1/libc/SYSCALLS.TXT) and [app seccomp policy](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r1/libc/SECCOMP_BLOCKLIST_APP.TXT) were checked for close, inotify and clock calls. Runtime failures remain explicit; compilation or the syscall list is not proof that a vendor policy permits them. No Arm or x86 instruction/register assumptions are used.

KernelSU provides a historical hypothesis, not a unique signature:

- [08a3b087 throne tracker](https://github.com/tiann/KernelSU/blob/08a3b087/kernel/manager/throne_tracker.c) included a manager-absent full scan of packages.list and APKs.
- [ab23091e package observer fix](https://github.com/tiann/KernelSU/commit/ab23091edfeddc774e1e880b0919b211808a193e) moves the normal `track_throne` call to `TWA_RESUME` task_work after leaving the notification reader and rename locks. A positive is not expected from that normal path. Kernel-thread, allocation or queueing failure fallbacks still call inline, so timing cannot establish a version.
- [6b5f55bd manager-name pinning](https://github.com/tiann/KernelSU/commit/6b5f55bd95e9c412bafd1dbe1431032cd32baa20) additionally removes the manager-absent full scan. Forks may retain other behavior.

## Ownership and acquisition

Everything lives in `feature/nativeroot`. Domain types and statistics have no Android dependency. Data owns the permission stimulus, consent storage, private carrier and narrow JNI bridge. Presentation projects the typed observation into a detection-method row, detail/copy text and the existing SDK report. UI owns the consent prompt and setting. No new central registry entry or cross-feature helper is needed.

The manifest contributes `${applicationId}.duckdetector.srcu` and the non-exported `:srcu_timing` service. It is an ordinary same-UID process, because an isolated UID cannot own the permission tree. It does not share the app zygote carrier. The AAR host's application ID resolves the tree placeholder.

Each native window prepares the first inotify FD and mark on thread B, then signals readiness. Thread A records CLOCK_MONOTONIC, starts B and executes the Java stimulus in the same JNI invocation. B times complete closes, prepares fresh instances and pauses 1 ms between samples. No Binder, allocation, JNI, logging or verdict computation occurs inside a timed close. A records its ending timestamp after the stimulus and readback, then joins B. `close(EINTR)` is never retried. Arrays are bounded at 128 samples per window; a quota hit is inconclusive.

The synchronous API/readback window is broader than the actual kernel reader interval. A close starting inside it is only a candidate overlap. No observed package-list write or SRCU entry is claimed.

After a warmup, 12 rounds randomize these three arms, with a 25 ms washout between arms:

1. Idle: matched-duration window with no package change.
2. Stimulated: synchronous alternating permission label and readback.
3. Sequential: apply the same change first, then collect a matched idle window.

Idle duration follows the previous stimulated window, clamped to 20–500 ms. Washout does not establish that global readers are idle. Cleanup removes the private dynamic permission and verifies absence. Existing permission names are refused before any mutation, even if they belong to this package; the diagnostic never overwrites an existing declaration.

The host uses asynchronous Messenger request/reply and a 30 s response deadline. The carrier uses an independent 25 s watchdog. Host unbinding asks acquisition to stop between windows while retaining cleanup. A feature-owned mutex rejects overlapping host requests; the carrier independently rejects concurrent requests process-wide, including from a new service instance created by a rebind while an earlier run is still finishing. Process-name validation prevents a manifest override from making the watchdog kill the host.

The watchdog bounds ordinary host waiting. A close stuck in uninterruptible kernel sleep can survive SIGKILL; system_server can also remain blocked. The pre-fix KernelSU ABBA deadlock is a documented risk of the stimulus. Process isolation cannot fix kernel recovery. This is why the experiment requires explicit consent and remains disabled by default.

If process death interrupts cleanup, the report says cleanup is unconfirmed. A subsequent run refuses the stale sample name. An SDK host can remove its own `${applicationId}.duckdetector.srcu.sample` with `PackageManager.removePermission` after confirming no experiment is active; the diagnostic does not automatically assume ownership of pre-existing state.

## Interpretation

A scored observation requires cleanup, all 12 complete rounds and at least eight usable candidate-overlap samples in every arm. Fast stimulus windows may supply fewer samples; these are inconclusive. No fixed millisecond root threshold is used.

The control scale is the maximum of pooled idle/sequential median absolute deviations, one tenth of either control median and 1 ns. This relative floor prevents a near-zero MAD from turning small jitter into a warning. A round is delayed when stimulated p95 exceeds the greater control p95 by more than six scales. A warning needs 10 delayed rounds, at least three in each four-round block, and a pooled p95 gap above six scales. A sequential median shift above six scales or an unstable idle right tail invalidates interpretation. Partial replication is inconclusive.

The criterion is experimental and uncalibrated. Background fsnotify readers, workqueue batching, CPU scheduling, thermal/load changes, OEM persistence, PackageManager locks and concurrent detector scans can cause false positives or conceal delays. The result is WARNING at most, never DANGER or a root-family flag. Negative, unsupported or failed results cannot exclude any root solution. An unsupported Android or kernel does not reduce Native Root coverage, because the experiment never applied there; an applicable run that fails or stays inconclusive does. Other Native Root findings retain their own semantics.

Native stage/errno, collection failure, cleanup state and bounded raw timestamps survive the text protocol and reach detail/copy/SDK evidence. A malformed or oversized reply is a failure, never a negative result.

## Validation and remaining device work

JVM tests cover repeated delays, isolated outliers, control drift, near-zero noise, incomplete/quota/failed samples, collection failures, applicability gates, protocol bounds and projection. A host C++ test compiles the production sampler with injected I/O and checks readiness ordering, FD cleanup, close EINTR, clock errors and quotas; host shims do not validate kernel SRCU behavior. The APK native build covers arm64-v8a, armeabi-v7a, x86 and x86_64. SDK manifest merging and AAR consumption are build checks.

No connected Android device was available for this change. Before interpreting real results, collect labelled raw runs on stock ACK devices and fixed KernelSU devices with and without the manager, including load controls, cancellation, service death and cleanup. Confirm dynamic-permission changes actually rewrite packages.list on each device's backend and inspect the device/vendor fsnotify sources. Compare retained pre-fix forks only on recoverable lab devices given the lock-inversion risk. Threshold calibration, false-positive rates and runtime overhead remain open; changing the default requires those results.
