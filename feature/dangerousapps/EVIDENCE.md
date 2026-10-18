# Dangerous Apps evidence record

Status: reviewed

HMA behavior checks, including the seccomp getpriority probe, have the coverage and limitations described below.

The Dangerous Apps detector asks whether root managers, hooking frameworks and similar tools are installed, including when package visibility filtering or hiding modules keep them out of PackageManager.

## Signals

### PackageManager inventory

- Observable signal: installed packages from PackageManager, and targets PackageManager omits although other methods find them.
- Producing subsystem: PackageManager and its package visibility filtering.
- Mechanism: an installed target appears in PackageManager unless visibility filtering or a hiding module removes it.
- References: frameworks/base core/java/android/content/pm/PackageManager.java; capability/packageinventory/EVIDENCE.md.
- Applicability: full visibility needs QUERY_ALL_PACKAGES from the host.
- Visibility limits: restricted visibility is reported; hidden-from-PackageManager findings are only computed under full visibility.
- Result states: detected, hidden from PackageManager, restricted, clean.
- Interpretation: an installed target is a finding at its category's severity; hiding from PackageManager is stronger.

### Filesystem and provider methods

- Observable signal: package contexts, APK file descriptors, directory listings with zero-width and ignorable codepoints, FUSE stats, the native /data/data stat and tool-specific special paths.
- Producing subsystem: the filesystem through DAC, SELinux and MediaProvider's FUSE layer.
- Mechanism: each method reaches the package's files by a path PackageManager filtering does not control.
- References: capability/packageinventory/EVIDENCE.md (data directory stat); kernel/common Documentation/filesystems/proc.rst for fd views. Discovery only for the Unicode path bypass methods.
- Applicability: every release; FUSE behaviour depends on the MediaProvider version.
- Visibility limits: the native stat can fail to run, which the report records as an issue instead of no hits.
- Result states: detected by method, method not run, clean.
- Interpretation: each method adds evidence for the same package; findings list every method that saw it.

### Tool-specific channels

- Observable signal: the Scene loopback and broadcast channels, Thanox IPC, and enabled accessibility services.
- Producing subsystem: the tools' own services.
- Mechanism: these tools answer on fixed local channels.
- References: Discovery only: the channels follow each tool's observed behaviour.
- Applicability: every release.
- Visibility limits: a tool that is installed but not running does not answer.
- Result states: detected, clean.
- Interpretation: an answering tool is a finding for that tool.


## HMA behavior checks

### Provenance

The detection-vector report for these checks comes from [frknkrc44](https://github.com/frknkrc44),
maintainer of [HMA-OSS](https://github.com/frknkrc44/HMA-OSS), as supplied with the feature request.
Credit for that report belongs to frknkrc44, not Chunqiu or Wuying. This attribution describes the
source used here; it makes no claim about independent prior discoveries. The seccomp listener
mechanism is probed directly; non-seccomp mechanisms are outside this check. No third-party code or
text is copied or adapted; the implementation uses the documented mechanisms and independent tests
below.

### Report coverage

| Supplied report point | Implemented check | Evidence level |
| --- | --- | --- |
| 1.1 Broadcast cross-user exception suppression | BROADCAST_CROSS_USER | Repeated exception difference with caller controls |
| 1.2 Missing resultTo delivery | BROADCAST_RESULT_COMPLETION | Repeated deadline asymmetry with interleaved controls; lower confidence |
| 1.2 Incorrect manual resultTo delivery | BROADCAST_RESULT_TO | Repeated final flag/result/intent difference with caller controls |
| 2.0 getPackageInfo exception suppression | PACKAGE_INFO_EXCEPTION | Repeated permission exception difference |
| 2.0 getApplicationInfo exception suppression | APPLICATION_INFO_EXCEPTION | Repeated permission exception difference |
| 3.0 getpriority visibility of running hidden UIDs | UID_TASK_VISIBILITY | Repeated task/association difference, without package identity |
| 3.0 seccomp getpriority interception | SECCOMP_UID_FILTER | NEW_LISTENER EBUSY, suppressed notification or trap; kernel-version-gated |

The seccomp approach in point 3.0 is probed directly. A
[NEW_LISTENER install returns EBUSY](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/seccomp.c?h=v5.0)
when an existing filter already owns a listener; when no listener exists, the probe counts
getpriority notifications and reports queries a foreign filter answered first. Non-seccomp
mechanisms are outside this check. Refused or incomplete native queries retain their explicit
states; their absence cannot establish that no app is hidden.

### Permission-exception consistency

- Observable signal: repeated target-package calls return normally or throw NameNotFoundException,
  while caller-package controls before and after both throw SecurityException.
- Producing subsystem: ActivityManager's incoming-user permission checks and PackageManager's
  MATCH_ANY_USER flag permission enforcement, including the public Java wrapper's null conversion.
- Mechanism: sendBroadcastAsUser targets another user with an explicit, randomly named absent
  receiver. Package/application-info calls use AOSP's hidden MATCH_ANY_USER flag (0x00400000) for
  the current user; that flag requires cross-user permission even for the caller's user. No receiver
  is registered, no target component is launched, and no global hidden-API exemption is installed.
- Primary references: Android [Context](https://developer.android.com/reference/android/content/Context)
  and [PackageManager](https://developer.android.com/reference/android/content/pm/PackageManager);
  AOSP Android 10 [PackageManagerService.updateFlagsForPackage](https://android.googlesource.com/platform/frameworks/base/+/android-10.0.0_r1/services/core/java/com/android/server/pm/PackageManagerService.java),
  Android 14 [ComputerEngine](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/services/core/java/com/android/server/pm/ComputerEngine.java),
  [ApplicationPackageManager](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/app/ApplicationPackageManager.java),
  [ContextImpl](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/app/ContextImpl.java),
  [UserController.handleIncomingUser](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/services/core/java/com/android/server/am/UserController.java),
  and Android 16 [ComputerEngine](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/ComputerEngine.java)
  / [BroadcastController](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/am/BroadcastController.java).
  Android 17 keeps the same MATCH_ANY_USER requirement
  ([ComputerEngine.updateFlagsForPackage](https://android.googlesource.com/platform/frameworks/base/+/android-17.0.0_r1/services/core/java/com/android/server/pm/ComputerEngine.java),
  [UserController.handleIncomingUser](https://android.googlesource.com/platform/frameworks/base/+/android-17.0.0_r1/services/core/java/com/android/server/am/UserController.java),
  [ApplicationPackageManager.getPackageInfoAsUser](https://android.googlesource.com/platform/frameworks/base/+/android-17.0.0_r1/core/java/android/app/ApplicationPackageManager.java)).
- Upstream implementation references: HMA-OSS [oss-164 BroadcastHook](https://github.com/frknkrc44/HMA-OSS/blob/oss-164/zygote/src/main/java/org/frknkrc44/hma_oss/zygote/hook/BroadcastHook.kt)
  returns before the framework permission path; [oss-173 PmsHookTargetBase](https://github.com/frknkrc44/HMA-OSS/blob/oss-173/zygote/src/main/java/org/frknkrc44/hma_oss/zygote/hook/PmsHookTargetBase.kt)
  preserves existing exceptions. These are version/configuration fingerprints, not generic Zygisk tests.
- Applicability: Android 10–17 (API 29–37); later releases explicitly return unsupported pending
  source verification. Privileged callers, OEM changes or failed hidden-method lookup invalidate
  controls and yield inconclusive results.
- Visibility limits: at most 128 distinct catalog targets absent from the current inventory are
  compared, prioritizing packages already corroborated by other probes before catalog order; the report retains the selected/total scope. AOSP package filtering
  alone does not establish a mismatch because permission checks precede target lookup.
- Result states: consistent in evaluated scope, inconsistent, inconclusive, partial, unavailable, unsupported.
- Interpretation: only repeated differences with passing controls produce warning-level evidence.
  NameNotFoundException alone is normal package-query behavior, not evidence of hiding.

### Ordered-broadcast final callback

- Observable signals: completion before a callback deadline, and separately final-receiver semantics
  (ordered=false, sticky=false, preserved result code/data/extras and original intent filter fields/token).
  These are two facets of the same broadcast mechanism, not independent corroborating detectors.
- Producing subsystem: framework broadcast queues, IApplicationThread and final IIntentReceiver delivery.
- Mechanism: sendOrderedBroadcast uses the same absent explicit component. Each target is submitted
  twice with successful caller-package callbacks required before, between and after the two calls.
  Each callback has a 1 s timeout; the target batch has an 8 s budget. Incomplete pairs are discarded
  and reduce coverage. Late callbacks are ignored after coroutine cancellation; no receiver is registered.
  These budgets bound asynchronous waits; a blocked synchronous Binder submission cannot be preempted
  by coroutine cancellation and may delay the scan.
- Primary references: Android [Context.sendOrderedBroadcast](https://developer.android.com/reference/android/content/Context#sendOrderedBroadcast(android.content.Intent,%20java.lang.String,%20android.content.BroadcastReceiver,%20android.os.Handler,%20int,%20java.lang.String,%20android.os.Bundle))
  documents the final result receiver; AOSP Android 10 [BroadcastQueue](https://android.googlesource.com/platform/frameworks/base/+/android-10.0.0_r1/services/core/java/com/android/server/am/BroadcastQueue.java)
  sends the final result with false/false; Android 14 [BroadcastQueueModernImpl.scheduleResultTo](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/services/core/java/com/android/server/am/BroadcastQueueModernImpl.java)
  and Android 16 [BroadcastQueueImpl.enqueueBroadcastLocked / scheduleResultTo](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/am/BroadcastQueueImpl.java)
  schedule the final receiver when no receivers matched, passing the original intent and initial
  results through IApplicationThread with ordered=false. No platform deadline of 1 s is guaranteed.
  Android 17's
  [BroadcastQueueImpl.scheduleResultTo](https://android.googlesource.com/platform/frameworks/base/+/android-17.0.0_r1/services/core/java/com/android/server/am/BroadcastQueueImpl.java)
  keeps the same ordered=false contract.
- Upstream references: HMA-OSS [oss-164 BroadcastHook](https://github.com/frknkrc44/HMA-OSS/blob/oss-164/zygote/src/main/java/org/frknkrc44/hma_oss/zygote/hook/BroadcastHook.kt)
  returns before queuing and omits final result delivery; [oss-173 BroadcastHook](https://github.com/frknkrc44/HMA-OSS/blob/oss-173/zygote/src/main/java/org/frknkrc44/hma_oss/zygote/hook/BroadcastHook.kt)
  manually invokes performReceive with the BroadcastRecord.ordered flag.
- Applicability: API 29–37; up to 128 distinct targets absent from inventory. Already corroborated
  targets and targets showing repeated permission-exception anomalies receive priority within the
  callback budget. Scope and completed-pair counts remain visible; prioritization adds no confidence.
  The report does not assert the behavior of an unspecified newer HMA test build.
- Interpretation: repeated received callbacks with wrong flags/result/intent produce warning-level
  semantic evidence. Two target timeouts with three successful local controls produce a separate
  lower-confidence timing warning, never proof that callbacks were permanently dropped or that a
  particular module exists. A single timeout, failed control, denial, decoding failure or interrupted
  pair cannot produce this warning. Batch deadline exhaustion remains an explicit partial-coverage
  result even before the first pair completes; failed control fields remain visible separately from
  target failures. Callback-intent preservation additionally checks call correlation;
  intent replacement or a mismatched per-call token is a semantic difference. Expected intent fields
  are copied before submission so mutation of the submitted object does not alter the baseline.
- False positives and visibility limits: load, scheduling, freezing, OEM policy and transient system
  failures can delay callbacks selectively despite controls. Both completion and semantic checks
  preserve permission, failure and partial-coverage states. Bundle decoding failures are unavailable,
  rather than semantic mismatches or exceptions escaping on the application main thread.
- Result states: consistent, inconsistent, lower-confidence timing anomaly, inconclusive, partial,
  permission limited, unavailable, unsupported.

### UID task visibility through getpriority

- Observable signal: getpriority(PRIO_USER, uid) succeeds for an ordinary app UID while repeated
  PackageManager.getPackagesForUid queries return no package association.
- Producing subsystem: Android Common Kernel task/credential traversal, with the process's user and
  PID namespaces, independent of PackageManager's package filtering.
- Mechanism: syscall(SYS_getpriority) bypasses the getpriority libc wrapper. A disposable child checks
  its own UID, then queries this Android user's app IDs 10000–19999, excluding SDK-sandbox and isolated
  UID ranges. The child has a 500 ms scan budget, a 512-hit bound and the common runner's 1 s run /
  250 ms reap deadlines. Up to 16 unassociated UID candidates are queried again in children, bracketed
  by successful caller-package association controls. The raw kernel 1..40 return is converted to
  nice=20-return; failures, signals and seccomp refusal never become absence.
- Primary references: ACK android14-6.1 at `48e3cd973485465613da6d71fa17139773546573`, [kernel/sys.c:getpriority](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/kernel/sys.c)
  (`task_uid`, `task_pid_vnr`, initial ESRCH); the same traversal and return semantics in ACK
  android15-6.6 at [150617c4d667a241e52441e855befac0c5d6702b](https://android.googlesource.com/kernel/common/+/150617c4d667a241e52441e855befac0c5d6702b/kernel/sys.c)
  cover the 6.6 emulator comparison; AOSP Android 14
  [bionic getpriority.cpp](https://android.googlesource.com/platform/bionic/+/android-14.0.0_r1/libc/bionic/getpriority.cpp)
  and [UserHandle](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/os/UserHandle.java);
  [package visibility](https://developer.android.com/training/package-visibility);
  [JNI resolving native method names](https://docs.oracle.com/en/java/javase/17/docs/specs/jni/design.html#resolving-native-method-names).
- Applicability: built for arm64-v8a, armeabi-v7a, x86 and x86_64; full package visibility and an ordinary
  application UID are required. ACK 6.1 is a semantics reference, not a guarantee about OEM patches.
- Visibility limits: non-running apps have no task signal; package associations can change through
  uninstall/update, shared UIDs and OEM policy. PackageManager may also be hooked. A UID is not a
  package identity. A completed scan only covers the stated user/range at sampling time. Seccomp,
  namespaces and kernel filtering can hide tasks; no absent task means no installed package.
- Result states: consistent, inconsistent, inconclusive, partial, permission limited, unavailable,
  unsupported. A mismatch that identifies only a UID and not a package is a warning and never
  adds a named hidden package or red HMA alert.
  A completed scan must observe the live caller. A partial scan that visited the caller's UID but
  omitted it also invalidates the comparison.
  A partial scan that has not reached that UID remains partial; its start UID and visited count are
  retained so callers in secondary Android users receive the same control semantics.

### Seccomp getpriority interference

- Observable signal: the errno of a seccomp(SECCOMP_SET_MODE_FILTER,
  SECCOMP_FILTER_FLAG_NEW_LISTENER) install for a filter that returns USER_NOTIF for
  getpriority(PRIO_USER, *), and whether each query in the caller's app UID range produces a
  notification.
- Producing subsystem: the calling task's kernel seccomp filter stack and the
  [action-precedence loop](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/seccomp.c)
  in kernel/seccomp.c.
- Mechanism: a disposable child installs the listener filter, then forks a query child and services
  its notifications with
  [SECCOMP_USER_NOTIF_FLAG_CONTINUE](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html).
  The kernel evaluates every filter and runs the lowest action
  ([ACTION_ONLY](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/seccomp.c));
  [TRAP](https://man7.org/linux/man-pages/man2/seccomp.2.html) (0x00030000) and
  [ERRNO](https://man7.org/linux/man-pages/man2/seccomp.2.html) (0x00050000) outrank USER_NOTIF
  (0x7fc00000), so a foreign filter can answer a query without a notification. An existing listener
  makes the NEW_LISTENER install fail with EBUSY before any query runs
  ([Linux v5.0 init_listener](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/seccomp.c?h=v5.0),
  [ACK has_duplicate_listener](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/seccomp.c)).
  The listener and filter live only in the
  [disposable child](./data/src/main/cpp/dangerousapps/seccomp_uid_bridge.cpp); the app process's
  seccomp stack is not modified.
- Primary references: Linux v5.0 [kernel/seccomp.c init_listener](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/seccomp.c?h=v5.0)
  (EBUSY when an ancestor already has a listener), and the same duplicate-listener rule in ACK
  [android13-5.15](https://android.googlesource.com/kernel/common/+/refs/heads/android13-5.15/kernel/seccomp.c),
  [android14-6.1](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/seccomp.c),
  [android15-6.6](https://android.googlesource.com/kernel/common/+/refs/heads/android15-6.6/kernel/seccomp.c)
  and [android16-6.12](https://android.googlesource.com/kernel/common/+/refs/heads/android16-6.12/kernel/seccomp.c);
  the [ACK action loop's signed ACTION_ONLY comparison](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/kernel/seccomp.c),
  which makes the lowest action win; [seccomp(2) return actions](https://man7.org/linux/man-pages/man2/seccomp.2.html)
  and [seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html); Linux v4.19
  [kernel/seccomp.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/seccomp.c?h=v4.19)
  for the flag mask that rejects NEW_LISTENER before Linux 5.0; AOSP bionic
  [SECCOMP_ALLOWLIST_COMMON.TXT](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r1/libc/SECCOMP_ALLOWLIST_COMMON.TXT)
  (seccomp and clone are allowed for apps; Android 10 and 11 use the equivalent
  [SECCOMP_WHITELIST_COMMON.TXT](https://android.googlesource.com/platform/bionic/+/android-11.0.0_r1/libc/SECCOMP_WHITELIST_COMMON.TXT)) and
  [SYSCALLS.TXT](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r1/libc/SYSCALLS.TXT)
  (getpriority, ppoll, ioctl, wait4, kill, uname and setitimer; bionic's poll wrapper uses ppoll).
- Applicability: Android 10–17 (API 29–37) probe; EBUSY is interpreted only when the kernel is at
  least 5.0, the release that introduced
  [SECCOMP_RET_USER_NOTIF and NEW_LISTENER](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/kernel/seccomp.c?h=v5.0).
  Android apps carry
  [no_new_privs](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html) and the
  [bionic allowlist](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r1/libc/SECCOMP_ALLOWLIST_COMMON.TXT)
  includes the seccomp syscall. The probe runs in a disposable child and leaves no listener in the
  app process.
- Visibility limits: the probe observes only filters installed in this process; a module that does
  not target this package leaves no signal here. A non-seccomp mechanism is outside this check. A
  foreign listener from another module produces the same EBUSY evidence, and a foreign TRAP or
  ERRNO filter produces the same suppression evidence; the check never identifies a module. OEM
  seccomp policies can differ from
  [bionic](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r1/libc/SECCOMP_BLOCKLIST_APP.TXT).
  An incomplete query phase is reported as such and never converted into a suppression claim.
- Result states: consistent, inconsistent, inconclusive, permission limited, unavailable, unsupported.
- Interpretation: EBUSY with a valid NEW_LISTENER program on Linux >= 5.0, a suppressed
  getpriority notification, or a seccomp trap on the install/query path is warning-level seccomp
  interference evidence. A clean result covers the caller's app UID range at sampling time only and
  does not establish that no app is hidden.

### Validation coverage

Unit tests cover repeated permission controls, public-wrapper NameNotFoundException conversion,
failed controls, ordered/sticky/payload callback differences, timeout uncertainty, native payload
framing, raw priority conversion, partial scans and warning-level presentation. The seccomp
probe's payload framing, EBUSY kernel-version gate, suppression/trap classification and
presentation are covered by JVM tests. Callback tests also cover interleaved controls, paired
timeout asymmetry, call correlation, batch interruption and external cancellation. The native parent
validates child counts before indexing fixed buffers; Kotlin also rejects unsorted hits, UIDs beyond
the visited prefix and success states carrying collection errors. Native builds cover all four
supported ABIs. Device results for the original behavior checks are recorded after executing the
runtime checks; the seccomp probe also has a controlled positive and negative on an API 37
device below, plus JVM and build coverage. No HMA version or configuration is assumed from package presence
alone.

The monitored catalog includes `org.frknkrc44.hma_oss`, as declared by the upstream HMA-OSS
application and observed in the device package inventory. Target prioritization affects sampling
coverage only; it does not promote the corroborating probes into stronger evidence.


#### Release coverage of the framework contracts

The MATCH_ANY_USER permission requirement and final-callback ordered=false rule were also checked
in the intervening release sources:

| Android tag | Permission enforcement | Final callback |
| --- | --- | --- |
| android-11.0.0_r1 | [PackageManagerService](https://android.googlesource.com/platform/frameworks/base/+/android-11.0.0_r1/services/core/java/com/android/server/pm/PackageManagerService.java) | [BroadcastQueue](https://android.googlesource.com/platform/frameworks/base/+/android-11.0.0_r1/services/core/java/com/android/server/am/BroadcastQueue.java) |
| android-12.0.0_r1 | [PackageManagerService](https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/services/core/java/com/android/server/pm/PackageManagerService.java) | [BroadcastQueue](https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/services/core/java/com/android/server/am/BroadcastQueue.java) |
| android-13.0.0_r1 | [ComputerEngine](https://android.googlesource.com/platform/frameworks/base/+/android-13.0.0_r1/services/core/java/com/android/server/pm/ComputerEngine.java) | [BroadcastQueue](https://android.googlesource.com/platform/frameworks/base/+/android-13.0.0_r1/services/core/java/com/android/server/am/BroadcastQueue.java) |
| android-15.0.0_r1 | [ComputerEngine](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/services/core/java/com/android/server/pm/ComputerEngine.java) | [BroadcastQueueModernImpl](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/services/core/java/com/android/server/am/BroadcastQueueModernImpl.java) |
| android-16.0.0_r1 | ComputerEngine linked above | [BroadcastQueueImpl](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/am/BroadcastQueueImpl.java) |
| android-17.0.0_r1 | [ComputerEngine](https://android.googlesource.com/platform/frameworks/base/+/android-17.0.0_r1/services/core/java/com/android/server/pm/ComputerEngine.java) | [BroadcastQueueImpl](https://android.googlesource.com/platform/frameworks/base/+/android-17.0.0_r1/services/core/java/com/android/server/am/BroadcastQueueImpl.java) |

#### Device observations before callback-coverage revision (2026-10-18, Asia/Singapore)

PJX110, Android 16/API 36, security patch 2026-04-01, arm64, kernel
`6.1.141-android14-11-o-gd2a6093d5589`. Package metadata reports HMA-OSS `oss-162`
(versionCode 7304645); Duck Detector's blacklist scope is user-reported. Module configuration was
not changed. Two consecutive scanner/export runs completed successfully through the generic
DetectorRuntimeSmokeTest, with caller-package controls passing in each run:

| Check | Observed result in each run |
| --- | --- |
| Broadcast cross-user exception | 124/124 catalog targets repeated; no exception mismatch |
| getPackageInfo exception | 124/124 targets repeated; nine target package names had repeated exception mismatches |
| getApplicationInfo exception | 124/124 targets repeated; the same nine target names had repeated exception mismatches |
| Ordered-broadcast final result | 24/24 selected targets repeated; flags and payloads matched; overall catalog coverage remains partial (24/124) |
| getpriority UID visibility | 10000/10000 UIDs checked; 87 then 86 task UIDs; the same eight UIDs repeatedly lacked visible package associations; no recheck failure or recheck-limit truncation |

These runtime observations describe the original five-check implementation. The expanded callback
scope, interleaved controls and intent-token check still need a fresh PJX110 run: no physical device
was attached during the revision. The unit tests exercise missing-resultTo and wrong-resultTo paths
with structured observations, not an actual oss-164/173 installation.

#### Seccomp probe control run (2026-10-18)

Android 17/API 37, arm64, Linux 6.1. A controlled run with a pre-existing seccomp
user-notification listener for getpriority(PRIO_USER, *) produced
`Behavior mismatch observed`; the captured detail began
`seccomp(SECCOMP_SET_MODE_FILTER` (the EBUSY branch). A second run with the unmodified process
filter stack produced `Consistent in evaluated scope` with all 10000 queries notified. Both runs
used the same app build and package catalog. Scan duration is not used as evidence.

The nine queried names are behavior fingerprints, not proof that nine corresponding apps are
installed. The eight UIDs do not identify hidden packages. These observations do not validate
HMA-OSS 173's manual-resultTo positive case, a newer fixed test release, or an HMA-disabled/stock
baseline. No enforced seccomp-denial profile was installed; the seccomp probe installs an
ALLOW/USER_NOTIF listener only in a disposable child. Older Android releases and other ABIs have
source/build coverage, not device coverage.

Reproduce the runtime smoke check after building and installing the debug and androidTest APKs:

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb shell am instrument -w -r \
  -e class com.eltavine.duckdetector.DetectorRuntimeSmokeTest \
  -e detectorId dangerous_apps \
  com.eltavine.duckdetector.test/androidx.test.runner.AndroidJUnitRunner
adb logcat -d -s DetectorRuntimeSmoke:I
```

The context bootstrap instrumented test and MainActivity cold-launch smoke check also passed.
The runtime harness uses AndroidX Test Runner 1.7.0 with the existing JUnit extension 1.3.0;
[runner documentation](https://developer.android.com/training/testing/instrumented-tests/androidx-test-libraries/runner)
and [release notes](https://developer.android.com/jetpack/androidx/releases/test) establish the
runtime dependency. The HMA JVM tests cover the exception, callback, UID policy, seccomp listener
payload, native framing and presentation rules; the seccomp probe adds domain, payload and
presentation cases.


The following validation commands passed with the repository-pinned uihelper revision
`18bed84a78dd811889ea1813d6954a988e44d688`:

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest unitTest :app:lintDebug buildHealth :sdk:aar:publish :sdk:aar:verifySdkAar
./gradlew :build-logic:test
./gradlew -p samples/sdk-consumer assembleDebug
for s in .github/scripts/check-*.py; do python3 "$s" || exit 1; done
```

The SDK consumer is a separate build using only the published AAR and Maven dependencies. Both
Debug and Release native library builds completed for arm64-v8a, armeabi-v7a, x86 and x86_64.

#### Android 16 emulator comparison after callback-coverage revision

A read-only `duck_api36` AVD session ran the revised app and generic paired scanner/export smoke
test: `OK (1 test)`, two scans in 7.626 s. Image fingerprint:
`google/sdk_gphone64_arm64/emu64a:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys`,
security patch 2025-07-05, arm64, kernel `6.6.66-android15-8-gd0c43a640eab-ab13812146-4k`.
No HMA-OSS, LSPosed or Magisk manager package was listed in this session. This is an emulator
framework comparison, not a security guarantee or a replacement for module-positive device tests.

Both scans exposed 247 package names and evaluated all 124 catalog targets. The three exception
checks each observed the expected SecurityException in all 248 target calls. Both final-callback
checks completed all 124 pairs with passing local controls, no timeout and no flag/result/intent-token
difference. Each native scan covered 10,000 UIDs, found 48 task UIDs and no repeatedly unassociated
UID; caller controls passed and no recheck failed or reached its limit. The resulting headline was
`No known risky packages`. MainActivity also cold-launched successfully. The temporary emulator
session was stopped after testing without saving a snapshot.

The revised sources passed the full unit/app/lint/buildHealth/SDK command above, the standalone SDK
consumer build and all repository guards. These emulator observations apply to commit
`3db22f0a0dc3b94411320c786f17173b38a79a47`; current JVM coverage includes the HMA behavior, seccomp
listener and presentation tests. Device coverage
for oss-164 callback omission, oss-173 wrong final flags, newer fixed builds and enforced seccomp refusal
remains open; PJX110 observations above apply to the earlier implementation.

#### Partial-coverage control regression

The live-caller invariant also applies inside a visited prefix: native collection increments `checked`
for each consecutive UID starting at the recorded first UID, including ESRCH outcomes. If that
prefix contains the live caller but no caller task is reported, foreign UID claims are suppressed
as inconclusive. If the prefix ends before the caller, no omitted-caller contradiction is inferred.
Tests cover the exact boundary and a secondary Android user range. These are collection controls,
not an additional independent HMA signal.

Callback batch exhaustion before any complete target/control pair now reports partial coverage;
it cannot become a missing-callback finding. Control fields and the batch-deadline flag distinguish
this from callback denial or failure. The earlier emulator observations above predate these reducer
refinements; no new physical-device run was available for this revision. The four added regressions
failed before the fixes and passed afterward. Validation for these refinements uses:

```sh
./gradlew unitTest :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug :sdk:aar:publish :sdk:aar:verifySdkAar
./gradlew -p samples/sdk-consumer assembleDebug
for s in .github/scripts/check-*.py; do python3 "$s" || exit 1; done
```
