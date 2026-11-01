# Dangerous Apps evidence record

Status: reviewed

HMA behavior checks, including the seccomp getpriority probe, have the coverage and limitations described below.

The Dangerous Apps detector asks whether root managers, hooking frameworks and similar tools are installed, including when package visibility filtering or hiding modules keep them out of PackageManager. It separately reports monitored package names present in this boot's package change history, without treating that history as current installation evidence.

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

### Package changes since boot

- Observable signal: exact monitored package names returned by `PackageManager.getChangedPackages(0)`,
  with the returned sequence number when present. Only catalog matches are retained; unrelated
  names in the platform response are discarded.
- Producing subsystem: the current Android user's PackageManager change tracker and its
  package-visibility filtering, reached through the public `ApplicationPackageManager` wrapper.
- Mechanism: PackageManager records package additions, updates and removals. Every scan queries
  from sequence zero, without persisting a cursor or results across scans or reboots. The tracker
  coalesces repeated changes for a package; this is not an ordered event log. The API exposes no
  event kind, event timestamp, signing certificate or proof of current installation.
- References: Android [getChangedPackages](https://developer.android.com/reference/android/content/pm/PackageManager#getChangedPackages(int))
  and [ChangedPackages](https://developer.android.com/reference/android/content/pm/ChangedPackages);
  AOSP Android 12 [PackageManagerService.getChangedPackages](https://android.googlesource.com/platform/frameworks/base/+/android-12.0.0_r1/services/core/java/com/android/server/pm/PackageManagerService.java),
  Android 14 [PackageManagerService](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/services/core/java/com/android/server/pm/PackageManagerService.java),
  Android 16 [PackageManagerService](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageManagerService.java),
  [ComputerEngine.shouldFilterApplication](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/ComputerEngine.java),
  [ChangedPackagesTracker](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/ChangedPackagesTracker.java)
  and [ApplicationPackageManager](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/app/ApplicationPackageManager.java).
- Applicability: public API since API 26, below this project's minimum API 29, on every supported
  ABI. Records and sequence numbers reset on boot. The query uses the caller's user and grants no
  cross-user access. No native code, hidden APIs, added permissions or global hooks are required.
- Visibility limits: the checked Android 12–16 release implementations filter against current
  package state. In Android 16, an ordinary non-instant, non-SDK-sandbox caller can retain a change
  whose package state is null, because this path passes `filterUninstall=false`. Thus a completely
  removed package can remain visible after installation-time filtering hid it. Removal from only
  one user, retained package data, OEM changes and hiding-module versions need not behave alike.
  This behavior is explanatory, not a required detection invariant. A null or empty response means
  no visible target changes, never that a package was never installed; hiding can also filter the API.
- Result states: not collected, available with or without catalog matches, permission denied,
  query unavailable, invalid response. A non-null response must advance beyond sequence zero and
  contain no null or blank package names. Empty filtered responses retain a valid returned sequence.
  Cancellation propagates instead of becoming a negative finding.
- Interpretation: matches are informational history evidence with current installation, running
  state and concealment unconfirmed. Normal uninstallation produces the same evidence. History
  has its own card section and export block; it never changes installed hits, hidden counts,
  HMA corroboration inputs or current-package detection methods. An incomplete query prevents an
  otherwise all-clear result. Stronger existing findings keep their original severity.

Detection-vector credit: [FldBudin](https://github.com/FldBudin) and
[aviraxp](https://github.com/aviraxp). The attribution concerns this vector, without assigning
priority over independent discoveries or importing third-party implementation code.

Verification includes eight JVM probe regressions and seven presentation/status/export regressions:
exact catalog matching and deduplication; filtered empty and null responses; sequence reset between
scans; permission, service and malformed-response failures; cancellation; independent history versus
installed/hidden counts and severity; and retention of inventory/behavior limitations.

The owning data module's `PackageChangeHistoryRuntimeTest` exercises the real public API twice per
invocation. Android 16 / API 36 arm64 emulator observations use fingerprint
`google/sdk_gphone64_arm64/emu64a:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys`, security patch
`2025-07-05`. A code-free APK fixture uses the monitored name `com.tsng.hidemyapplist`; it contains
no HMA implementation. The test host declares neither `QUERY_ALL_PACKAGES` nor a query for the
fixture. Before installation the target was absent from both queries. After installation it remained
invisible to both package-info and change-history queries. Complete normal removal made its change
record visible while package-info still could not resolve it. Both queries in each invocation agreed.
After reboot, both queries returned no target match and no sequence number, so the removed fixture's
previous-boot evidence was not retained. All four lifecycle stages passed their runtime assertions.
This validates stock package-visibility/removal behavior, without establishing the behavior of any
HMA release, retained-data removal, multi-user removal, OEM firmware or physical device.

To repeat the fixture lifecycle test, build `:feature:dangerousapps:data:assembleDebugAndroidTest`,
install its APK, and install/remove a disposable APK with that monitored package name. Invoke:

```sh
adb shell am instrument -w -r \
  -e class com.eltavine.duckdetector.features.dangerousapps.data.probes.PackageChangeHistoryRuntimeTest \
  -e historyPackage com.tsng.hidemyapplist \
  -e expectHistoryMatch true -e expectPackageVisible false \
  com.eltavine.duckdetector.features.dangerousapps.data.test/androidx.test.runner.AndroidJUnitRunner
```

Use `expectHistoryMatch false` before installation and while the fixture is installed under restricted
visibility. After complete removal, use `true`; after reboot use `false`. These expectations describe
the tested stock API 36 host, not a requirement for all supported systems. A host that explicitly
queries the target or has broad visibility can also observe its installation-time change.

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

- Observable signal: the Scene loopback and broadcast channels and enabled accessibility services.
- Producing subsystem: the tools' own services.
- Mechanism: these tools answer on fixed local channels.
- References: Discovery only: the channels follow each tool's observed behaviour.
- Applicability: every release.
- Visibility limits: a tool that is installed but not running does not answer.
- Result states: detected, clean.
- Interpretation: an answering tool is a finding for that tool.

### Thanox runtime IPC

- Observable signal: the custom transaction on Android's system `dropbox` service returns a strong Binder whose interface descriptor is exactly `github.tornaco.android.thanos.core.IThanos`.
- Producing subsystem: Binder userspace dispatch and the Thanox DropBox service proxy. The system `dropbox` registration alone identifies Android's diagnostic service, not Thanox.
- Mechanism: send the IThanos interface token with the upstream transaction code, require the transaction to be handled, read the raw returned Binder and verify that Binder's descriptor. The reply has no ordinary AIDL exception header. A nonempty reply, `transact=true`, or a matching descriptor on the outer system-service Binder is insufficient.
- References: Android [Context.DROPBOX_SERVICE](https://developer.android.com/reference/android/content/Context#DROPBOX_SERVICE) and [IBinder](https://developer.android.com/reference/android/os/IBinder); AOSP Android 16 [Binder.execTransactInternal](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/os/Binder.java), which serializes remote exceptions and returns true; Thanox commit `d964e8938f16fce086ff5febbf99b4cabd86cfc1` [DropBoxManagerProxyProvider](https://github.com/Tornaco/Thanox/blob/d964e8938f16fce086ff5febbf99b4cabd86cfc1/android/android_framework/patch-magisk/bridge/src/main/java/github/tornaco/android/thanox/magisk/bridge/proxy/content/DropBoxManagerProxyProvider.java), [ThanosManagerNative](https://github.com/Tornaco/Thanox/blob/d964e8938f16fce086ff5febbf99b4cabd86cfc1/android/android_framework/base/src/main/java/github/tornaco/android/thanos/core/app/ThanosManagerNative.java) and [IThanos.aidl](https://github.com/Tornaco/Thanox/blob/d964e8938f16fce086ff5febbf99b4cabd86cfc1/android/android_framework/base/src/main/java/github/tornaco/android/thanos/core/IThanos.aidl).
- Applicability: public Binder/Parcel operations on the project's Android API 29+ baseline, every ABI; service lookup uses the existing hidden ServiceManager adapter. Protocol compatibility is established against the pinned Thanox implementation, not every release or fork. No OEM exemption or additional permission is used.
- Visibility limits: a disabled, blocked or changed service can evade this channel; interface descriptors are not cryptographic identities. A matching runtime server does not prove the manager APK is installed for the current user or absent from PackageManager due to concealment. Synchronous Binder calls have no probe-enforced deadline; cancellation propagates when control returns and Parcels are recycled.
- Result states: not collected, transaction unhandled/no compatible service observed, matching runtime interface, unavailable, inconclusive. Empty/null/malformed replies and wrong descriptors never become package hits; transport and lookup failures never become a clean negative.
- Interpretation: a matching interface is a separate runtime warning. It does not add to installed-package findings, hidden counts or HMA corroboration. Incomplete IPC coverage prevents an otherwise all-clear result; independent package and HMA evidence retain their previous grading. This addresses issue #379's permissive nonempty-reply rule without assuming what the OriginOS service actually returned.

`ThanoxIpcRuntimeTest` exercises actual Android Parcel/Binder objects with valid-token enforcement, a matching server, serialized remote exceptions, nonempty AIDL success headers without a Binder, empty/null replies, wrong/missing descriptors, lookup and transport failures, cancellation and the stock framework service. The presentation and hidden-package policy regressions verify that runtime results never fabricate package installation or HMA concealment.

All 14 runtime cases passed on arm64 API 29 (`google/sdk_gphone64_arm64/emulator64_arm64:10/QSR1.211112.011/13135432:userdebug/dev-keys`) and API 36 (`google/sdk_gphone64_arm64/emu64a:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys`) emulators. The real framework DropBox query returned `NOT_OBSERVED` on both. Positive and error-response cases use local Binder fixtures, not an installed Thanox release or an OriginOS device. This validates the Parcel protocol handling, not every OEM service implementation.

To repeat, build `:feature:dangerousapps:data:assembleDebugAndroidTest`, install the test APK, then run `adb shell am instrument -w -r -e class com.eltavine.duckdetector.features.dangerousapps.data.probes.ThanoxIpcRuntimeTest com.eltavine.duckdetector.features.dangerousapps.data.test/androidx.test.runner.AndroidJUnitRunner` on a stock test emulator.


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

The seccomp extension was introduced by KodateMitsuru in PR #390. The broader detection-vector
report remains attributed to frknkrc44 above; this extension is a separate observation of the
filter stack, not an implementation of the concealment countermeasures named in that report.

- Observable signals: an actual NEW_LISTENER install returning EBUSY; missing notifications after
  the entire query range completes; or a query TRAP whose siginfo identifies getpriority on the
  compiled ABI. None of these identifies HMA or a specific filtering module.
- Producing subsystem: the inherited kernel seccomp stack. ACK's action-precedence loop selects
  the highest-priority action, and its duplicate-listener check can reject another listener.
- Mechanism: a disposable coordinator checks GET_NOTIF_SIZES against its bounded notification
  structures, prepares no_new_privs and installs an ABI-checked filter. Its query child probes the
  current user's ordinary app UID range. Accepted notifications receive a synthetic zero result
  with flags=0: the underlying priority syscall need not execute to observe filter precedence.
  This avoids CONTINUE, which Linux 5.0's seccomp_notify_send rejects. The separate UID-visibility
  probe still performs real priority queries.
- Primary references: ACK android14-6.1 at
  [48e3cd973485465613da6d71fa17139773546573:kernel/seccomp.c](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/kernel/seccomp.c)
  (`has_duplicate_listener`, `seccomp_set_mode_filter`, `seccomp_notify_recv/send`, action loop);
  matching ACK android15-6.6 at
  [150617c4d667a241e52441e855befac0c5d6702b:kernel/seccomp.c](https://android.googlesource.com/kernel/common/+/150617c4d667a241e52441e855befac0c5d6702b/kernel/seccomp.c)
  for the emulator kernel family;
  [Linux v5.0 seccomp.c](https://github.com/torvalds/linux/blob/v5.0/kernel/seccomp.c)
  (`init_listener` and the requirement that notification response flags be zero);
  [kernel seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
  (architecture checks, runtime notification sizes and action precedence);
  [ACK signal delivery](https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/kernel/seccomp.c)
  (`seccomp_send_sigsys` includes syscall and architecture);
  [PR_SET_PDEATHSIG](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).
  Framework API 37 contracts were independently checked in the Android 17 ComputerEngine,
  ApplicationPackageManager, UserController and BroadcastQueueImpl sources linked below.
- Lifetime and bounds: filters remain in disposable descendants. The query child sets a parent-death
  SIGKILL, checks the parent PID to close the setup race, and requires a working 3 s alarm. It closes
  its copy of the report descriptor. The coordinator uses a 1.8 s query budget and bounded nonblocking
  reaping after cancellation. It owns SIGCHLD handling only in the disposable coordinator and avoids
  signaling a PID when waitpid reports lost child ownership. The common runner has 2.5 s run / 250 ms reap deadlines. Kernel tasks
  temporarily stuck in an uninterruptible state can still delay final destruction. Poll/send EINTR
  handling retains deadlines; a blocked notification ioctl is bounded by coordinator termination.
- Applicability: Android 10–17/API 29–37, four supported ABIs. The runtime size handshake, rather
  than a release-number assumption, checks notification ABI compatibility. EBUSY is interpreted
  conservatively only on kernel major >= 5. Older kernels/backports and unknown versions may be
  unsupported or inconclusive. Linux 5.0 compatibility is source-verified, not device-tested.
- Visibility limits: an unrelated listener has the same collision signal. An inherited filter can
  synthesize EBUSY, and an intercepted syscall wrapper can also affect observations. Successful
  notifications exclude only higher-priority suppression of these calls; they do not exclude
  all filters or kernel-based hiding. OEM policy may differ. Query suppression is interpreted only
  after successful completion, with consistent counts and suppression endpoints.
- Failure states: an unqualified coordinator SIGSYS is permission limited. A query SIGSYS without
  syscall/ABI attribution, other signals, timeout or service failure remains inconclusive/unavailable.
  No setup trap is promoted to a getpriority finding. Errors in the capability/privilege setup are
  not listener-collision evidence. Contradictory native payload errors/counts are rejected.
- Interpretation: warning-level evidence requires an observed listener collision, complete-range
  suppression, or a specifically attributed getpriority TRAP. A completed clean label also requires
  the caller notification control. Incomplete or refused checks prevent an all-clear conclusion.

### Experimental UID permission visibility

- Observable signal: a current-user ordinary application UID repeatedly holds a selected non-instant
  permission while fresh package-service queries expose no package association, with successful
  caller association, caller INTERNET state and empty-permission denial controls before and after.
- Producing subsystem: PermissionService UID permission state and ComputerEngine package visibility.
- Mechanism: Android 15–17 use AccessCheckingService's PermissionService. Its checkUidPermission
  obtains the installed package with getPackage(uid), whose internal lookup uses SYSTEM_UID, then
  reads permission state without the legacy caller filter. getPackagesForUid instead filters using
  the actual caller. The feature-owned IPackageManager proxy avoids both Java clients' caches and
  uses generated method signatures rather than hard-coded transaction numbers. It does not change
  process-global hidden-API exemptions or cache settings. RECEIVE_BOOT_COMPLETED, ACCESS_WIFI_STATE
  and REORDER_TASKS lack the instant protection flag in all three reviewed manifests; active platform
  definitions are checked again. PermissionService denies these permissions to instant apps.
- References: Android [Context.checkPermission](https://developer.android.com/reference/android/content/Context)
  and [package visibility](https://developer.android.com/training/package-visibility/declaring);
  AOSP Android 15 [PermissionManager](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/core/java/android/permission/PermissionManager.java)
  / [PermissionManagerService](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/services/core/java/com/android/server/pm/permission/PermissionManagerService.java)
  / [PermissionService](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/services/permission/java/com/android/server/permission/access/permission/PermissionService.kt);
  Android 16 [PermissionService](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/permission/java/com/android/server/permission/access/permission/PermissionService.kt),
  [ComputerEngine](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/ComputerEngine.java),
  [permission definitions](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/res/AndroidManifest.xml),
  [AIDL](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/content/pm/IPackageManager.aidl)
  and [client cache](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/app/ApplicationPackageManager.java).
  The same path was checked at Android 16 security pin e96ce2b091188de3bf9cf6385e50a4559839d921.
  Android 17 `android-17.0.0_r1` was checked at frameworks/base commit
  `94b4c163b7dfe5ce3607f7bb8456f9573f7de57d`:
  [AccessCheckingService](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/services/permission/java/com/android/server/permission/access/AccessCheckingService.kt)
  registers PermissionService;
  [PermissionManagerService](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/services/core/java/com/android/server/pm/permission/PermissionManagerService.java)
  delegates UID checks to it;
  [PermissionService.checkUidPermission / isSinglePermissionGranted](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/services/permission/java/com/android/server/permission/access/permission/PermissionService.kt)
  retain the UID package lookup and instant-app exclusion.
  [PackageManagerInternalBase.getPackage](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/services/core/java/com/android/server/pm/PackageManagerInternalBase.java)
  reaches [ComputerEngine](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/services/core/java/com/android/server/pm/ComputerEngine.java),
  whose getPackage(uid) still uses SYSTEM_UID while getPackagesForUid uses Binder.getCallingUid().
  [IPackageManagerBase](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/services/core/java/com/android/server/pm/IPackageManagerBase.java)
  additionally enforces cross-user/profile access for package associations; this probe stays within
  the caller's user. The [AIDL signatures](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/core/java/android/content/pm/IPackageManager.aidl),
  [cached public package client](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/core/java/android/app/ApplicationPackageManager.java)
  and [non-instant permission definitions](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/core/res/AndroidManifest.xml)
  preserve the existing adapter and permission-selection contracts.
  HMA-OSS [1fe86ce2 PmsHookTargetBase](https://github.com/frknkrc44/HMA-OSS/blob/1fe86ce2b4a6f21197e6e92d15e054d609b7d77c/zygote/src/main/java/org/frknkrc44/hma_oss/zygote/hook/PmsHookTargetBase.kt)
  skips SYSTEM_UID; [PmsHookTarget33](https://github.com/frknkrc44/HMA-OSS/blob/1fe86ce2b4a6f21197e6e92d15e054d609b7d77c/zygote/src/main/java/org/frknkrc44/hma_oss/zygote/hook/PmsHookTarget33.kt)
  hooks the caller-filtered AppsFilter entry. This is a conditional mechanism reference, not an
  observed HMA-positive result. Android 13/14 r1 still select PermissionManagerServiceImpl and do
  not establish this same observation model; API 38 and later remain unsupported pending review.
- Applicability: API 35–37, ordinary caller UID, this Android user's app IDs 10000–19999, full normal
  package visibility and reviewed non-instant permission definitions. No target process, target
  package name or requested probe permission is required. There is a 1 s collection budget and a
  16-candidate verification bound. Synchronous Binder calls cannot be interrupted by that budget;
  cancellation is checked between calls and propagated through reflection wrappers.
- Visibility limits: ordinary visibility filtering reproduces the discrepancy without a module.
  INTERNET, ACCESS_NETWORK_STATE, WAKE_LOCK and VIBRATE allow instant apps and cannot qualify a hit.
  An unmodified instant app can hold INTERNET while remaining hidden even to QUERY_ALL_PACKAGES.
  Shared UID siblings can expose an association and suppress evidence. Packages holding none of the
  selected permissions are outside positive coverage. OEM policy, installation races, stale server
  state or other hooks remain alternative explanations; changing observations are inconclusive.
- Result states: consistent in evaluated scope, experimental discrepancy, partial, permission limited,
  unavailable, unsupported and inconclusive. Failed final controls discard all foreign UID claims.
  Per-UID permission names, evaluated prefix and verification limits remain visible in the report.
- Interpretation: experimental discrepancies are informational and never add a named package,
  increase hidden counts or establish HMA/KernelSU identity. A negative cannot exclude hiding.
  Task/permission UID intersections are annotated without changing severity or counting their shared
  package-association dependency as independent evidence. The original HH timing classifier is not
  implemented: the new permission path lacks its caller-filtered branch, and no timing ordering or
  thresholds have been measured for the old implementation.
  Android 17 has source verification and JVM regression coverage; its runtime behavior has not yet
  been validated on a device. The device validation below remains Android 16 coverage.

### Fresh UID association verification

The task-visibility comparison now uses the same feature-owned uncached package-service reader.
Repeated public getPackagesForUid calls can reuse a cached empty result and cannot by themselves
establish fresh service observations. Caller controls and foreign UID rechecks all reach the service;
query failures remain inconclusive and cancellation escapes. The kernel task contract and original
warning-level interpretation are retained. Instant-app visibility and OEM policy are explicit
alternative explanations. No global cache invalidation is used.

### UID permission validation matrix

An API 36 Google ARM64 emulator with SELinux Enforcing ran ordinary application UID observers;
no shell permission identity was adopted. Build fingerprint:
`google/sdk_gphone64_arm64/emu64a:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys`.
Fixtures had no code or components, so their permission observations did not require a running task.

| Fixture / observer | INTERNET | BOOT / WIFI | Package association | Expected interpretation |
| --- | --- | --- | --- | --- |
| Normal fixture / QUERY_ALL_PACKAGES | granted | granted / granted | present | consistent |
| Normal fixture / restricted | granted | granted / granted | absent | visibility limited; not hiding evidence |
| Instant fixture / QUERY_ALL_PACKAGES | granted | denied / denied | absent | excluded by non-instant permission rule |
| No-permission fixture / QUERY_ALL_PACKAGES | denied | denied / denied | present | absence of a grant does not exclude installation |
| Unassigned test UID / QUERY_ALL_PACKAGES | denied | denied / denied | absent | negative only for this fixture |

The initial INTERNET scan covered 10,000 app IDs: full visibility found 59 granted UIDs and zero
missing associations; restricted visibility found 36 missing associations. After installing the
instant fixture, full visibility found one INTERNET-only discrepancy and zero also granted BOOT or
WIFI. Restricted visibility still found 31 also-granted BOOT/WIFI discrepancies within its
INTERNET-granted subset. Both the full-visibility gate and non-instant permission gate are necessary.
These observations used public APIs to establish platform behavior; the shipped Binder adapter's
runtime validation is recorded separately below. Public Context.checkPermission documents a positive
PID, so the research harness's implementation-verified -1 PID is not used by the shipped UID-only
adapter. HMA-positive and OEM-device validation remain open; the result stays informational.

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
runtime checks; the original PR author supplied API 37 positive/negative observations below.
Those observations have not been independently reproduced. Review validation adds Android 16
emulator kernel cases and scanner/export coverage. No HMA version or configuration is assumed from package presence
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

#### Contributor-reported seccomp control run (2026-10-18, before review fixes)

The PR author reported Android 17/API 37, arm64, Linux 6.1. A controlled run with a pre-existing seccomp
user-notification listener for getpriority(PRIO_USER, *) produced
`Behavior mismatch observed`; the captured detail began
`seccomp(SECCOMP_SET_MODE_FILTER` (the EBUSY branch). A second run with the unmodified process
filter stack produced `Consistent in evaluated scope` with all 10000 queries notified. Both runs
used the same app build and package catalog. The repository does not include the raw logs or a
complete device fingerprint for this claim; it is retained as contributor-reported coverage, not an
independent review result. Scan duration is not used as evidence.

The nine queried names are behavior fingerprints, not proof that nine corresponding apps are
installed. The eight UIDs do not identify hidden packages. These observations do not validate
HMA-OSS 173's manual-resultTo positive case, a newer fixed test release, or an HMA-disabled/stock
baseline. The physical-device observations used no enforced seccomp-denial profile. Review experiments
install temporary refusal filters only in disposable emulator test processes; the application probe
installs its ALLOW/USER_NOTIF listener only in a disposable child. Older Android releases and other ABIs have
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

#### Seccomp review validation (Android 16 emulator)

The production native collector was compiled directly with NDK 30 for arm64 API 29 and tested in
an API 36 / kernel 6.6 read-only emulator session. Eight disposable-filter cases cover a complete
baseline, one-UID ERRNO suppression, an inherited listener, attributed query TRAP, unrelated setup
TRAP, unqualified SIGSYS kill, repeated EINTR deadline exhaustion, and coordinator death while a
query remains blocked on a listener held by the test supervisor. All eight passed. The supervisor
uses subreaper ownership to verify query cleanup; no test filter is installed in the app process.

```sh
python3 feature/dangerousapps/data/src/test/python/test_seccomp_uid_native.py \
  --ndk "$ANDROID_NDK_HOME" --serial emulator-5580 --adb "$ANDROID_HOME/platform-tools/adb"
```

The revised app's generic DetectorRuntimeSmokeTest completed two scanner/export runs (`OK (1 test)`,
9.887 s). Both seccomp checks received all 10,000 notifications with a caller control and produced a
consistent result. The emulator fingerprint/kernel match the Android 16 comparison above. No
physical device was attached, and the contributor's API 37 positive run was not reproduced.

Review verification passed: 58 HMA JVM regressions, the full unit/app/lint/SDK AAR command shown
above, the standalone SDK consumer and all repository guards. Debug and Release native builds
cover arm64-v8a, armeabi-v7a, x86 and x86_64. Native status claims require their supporting errno or
signal, and complete payloads cannot carry collection errors or impossible suppression endpoints.

### Shipped UID adapter runtime validation (2026-10-18)

The Debug APK and its existing DetectorRuntimeSmokeTest ran two complete Dangerous Apps scans
on the API 36 emulator described above, with ordinary non-running fixtures and an instant fixture
installed. Both scans passed the new probe's caller controls and reported zero experimental
permission/association discrepancies. The 1 s budget covered prefixes of 2,877 and 2,263 app IDs,
respectively, and both correctly reported PARTIAL rather than a full-space negative. Both prefixes
included the installed fixture UIDs. The task comparison scanned all 10,000 app IDs, saw 46 running
UIDs and zero repeatedly missing associations; all fresh package-query controls passed. This
validates generated proxy resolution, argument order, result decoding, partial coverage and
integration/export on this stock emulator. It does not validate HMA-positive behavior or OEM devices.

JVM regressions cover fresh changing associations, shared UID vetoes, INTERNET-only exclusion,
permission changes, failed final controls, missing private methods, permission denial, malformed
Binder values, nested reflection-wrapped cancellation, zero coverage, candidate caps, secondary
users, invalid/out-of-prefix evidence, informational presentation and correlation without escalation.
