# Issue #363: process-name residue source audit

Research date: 2026-10-09. Scope: the immutable revisions below, ordinary-app
collection through `heapresidue`, and process-name strings. Device validation is
pending. This record does not authorize a production rule or close #363.

## Decision

No new process-name rule is enabled. The audited sources establish one optional,
shared suffix candidate (`:magica_boot`), a generic AppZygote name, and service
class names produced in a different zygote. They do not establish reliable
visibility, renamed-manager coverage, or authentic root-family identity.

- Retain `:magica_boot` for controlled collision and visibility experiments only.
- Reject `_zygote` by itself as a root-family discriminator.
- Do not promote `MagicaService` class names into the main-zygote collector's
  rules without evidence that those requests reach its inherited heap.
- No stable process-name candidate was established for Magisk's audited hide
  transformation. This is a scoped negative result, not an impossibility proof.
- Numeric niceness does not recover historical `--nice-name` and has no validated
  family-specific rule here. No scheduling or privilege probe is added.

## Inputs and reproducibility

| Repository | Audited revision / applicability |
| --- | --- |
| frameworks/base | `e96ce2b091188de3bf9cf6385e50a4559839d921`, Android 16 security-release baseline |
| ART | `ba2c65bbab5a55e204b32d7b1480011a1bcb57f9`, the existing collector's format baseline |
| Android Common Kernel | `e65d894191a4f781c98ca3fe40d147d058483419`, android16-6.12 scheduling reference only |
| KernelSU | `df03912f70d92ff2aa9762ef82d607033d37e1da` |
| APatch | `526003615ce1783b285cd9340643898325e13dfe` |
| Magisk | `b268b361f0d46318986cf50eac62e90c2dbcd235` |

These are issue #363's fixed source baselines, not claims about every current
release, OEM, installed ART update, kernel, or downstream fork. Future revisions
require a new audit. `sources.json` pins 29 source files with SHA-256 and review
anchors; it contains no copied upstream implementation or device data.

From the repository root:

```sh
python3 feature/heapresidue/research/nice-name/audit_sources.py --fetch --cache-dir /tmp/duck-363-source-cache
python3 feature/heapresidue/research/nice-name/audit_sources.py --cache-dir /tmp/duck-363-source-cache
python3 -m unittest discover -s feature/heapresidue/research/nice-name -p 'test_*.py'
./gradlew :feature:heapresidue:data:testDebugUnitTest
```

The first command explicitly downloads public source; the second is offline.
The tool verifies inputs and prints anchor line numbers. It does not validate
the conclusions, execute upstream code, open a device, or analyze a raw heap.
Human review of the located control flow remains necessary.

Public API semantics were checked against Android's [service manifest][service-doc],
[receiver manifest][receiver-doc], [isolated binding][context-doc],
[application ID / namespace][namespace-doc], and [thread priority][priority-doc]
documentation. Web documentation is not revision-pinned; the implementation
claims below use immutable source. Existing transport, GC and SELinux limits
remain in [EVIDENCE.md](../../EVIDENCE.md) and are not redefined by this study.

## Parameter production and ownership

1. A manifest's `android:process` selects the component's process; a private
   colon suffix is app-scoped. The resolved installed manifest matters, not the
   source manifest alone. Application ID, namespace and component names can
   change independently; inspect the built APK for every renamed sample.
2. [ActiveServices.getProcessNameForService][active-services] uses the resolved
   service process for regular services. For ordinary isolated services it adds
   the component class name. Custom instance binding first appends the instance
   to that class name; shared-isolated and SDK sandbox branches differ. Therefore
   a class name is not universally a process name.
3. [ProcessList.startProcess][process-list] routes ordinary processes through
   `Process.start`, but AppZygote-backed children through `appZygote.startProcess`.
   [ActiveServices.bringUpServiceLocked][active-services] selects the latter from
   `FLAG_USE_APP_ZYGOTE`.
4. [AppZygote.connectToZygoteIfNeededLocked][app-zygote] asks the main zygote to
   start `AppZygoteInit` with its application's resolved process plus `_zygote`.
   This is a separate request from the isolated service child's request.
   [ZygoteProcess.startChildZygote][zygote-process] uses a generic entry-point/UUID
   socket name and supplies neither a package-name argument nor an app-data-dir
   argument in this startup request. Those cannot be assumed available alongside
   its nice name as an authenticated identity tuple.
5. [ZygoteProcess.startViaZygote][zygote-process] serializes the supplied name into
   `--nice-name`; [ZygoteArguments.parseArgs][zygote-arguments] stores its assigned
   value in `mNiceName`. The value field does not contain the parameter prefix.
6. [ART HPROF][art-hprof] serializes Java Strings through instance records and
   synthetic primitive value arrays. It does not authenticate their producer,
   certify process start success, or provide a trusted startup-event timestamp.

Possible name production is source-established. Survival until DuckDetector's
heap freeze, inheritance by the chosen ABI/zygote, and coverage are unmeasured.
[ZygoteConnection][zygote-connection] has repeated native fork paths; the
[USAP path][zygote] parses inside the pool process. A collector's own startup
arguments do not demonstrate residue of another application's launch.

## Candidate ledger

| Candidate | Producer and trigger | Rename behavior / identity | Decision |
| --- | --- | --- | --- |
| `<resolved package>:magica_boot` | KernelSU/APatch boot receiver, if enabled and dispatched; not an isolated service | A package-only rename can preserve the literal suffix; shared across families and reproducible by a benign app | Experiment-only candidate; no root finding |
| `<default process>_zygote` | Framework startup of an AppZygote when its service needs one | Default process normally follows the installed package; suffix is generic Android behavior | Reject as family rule |
| `<service process>:me.weishu.kernelsu.magica.MagicaService` or APatch equivalent | Framework request to the app's own AppZygote; service class as resolved in the installed APK | Class may survive an applicationId-only change, but component rewriting can remove it | Outside established main-zygote visibility; no rule |
| Hidden Magisk package or component name | Repacked stub's installed manifest | Package and placeholder components are randomized in the audited transformation | No stable nice-name candidate established |
| Negative/nondefault numeric nice | Scheduler state, not naming | Legitimate changes and permission/limit conditions exist | Reject as independent root rule |

### KernelSU: the boot and direct-service routes are distinct

The [manifest][ksu-manifest] gives the receiver `:magica_boot`, disables it by
default, and declares `MagicaService` isolated with AppZygote enabled. The
[settings implementation][ksu-settings] can enable the receiver through the
optional `autoJailbreak` setting. The [receiver][ksu-boot] accepts boot/custom
actions and returns before starting the service when `rootAvailable()` succeeds.

That check occurs **inside onReceive**, after the receiver process was selected.
It cannot imply that a `:magica_boot` name means root was unavailable or that
successful root prevents the receiver name from appearing.

The [home action][ksu-home] starts `MagicaService` directly; it does not require a
`:magica_boot` receiver launch. Thus a manager or its service can run while this
suffix is absent. The [preload callback][ksu-preload] runs in AppZygote and passes
application information to native code; class/log/library strings loaded there
must not be presumed present in the main zygote's heap.

The [build configuration][ksu-build] accepts `KSU_PACKAGE_NAME` while keeping a
fixed namespace. Preservation of final component names must still be checked
in the merged/release manifest; this audit did not build a renamed manager APK.

### APatch: shared suffix, different activation evidence

The [manifest][apatch-manifest] has the same disabled receiver suffix and isolated
AppZygote service; its receiver is exported in this baseline, unlike KernelSU's.
The [receiver][apatch-boot] similarly checks root availability after process
selection. The [installJailbreak route][apatch-cli] starts the service directly.

No `setComponentEnabledSetting` call was found in the fetched `app/src/main`
Java/Kotlin sources that enables this receiver. This bounded search does not
exclude native, external or downstream activation. Do not infer stable boot
coverage from a disabled manifest entry.

The [preload][apatch-preload] belongs to AppZygote. The [build file][apatch-build]
defines its namespace; a proposed applicationId-only variant is an experiment,
not a verified supported upstream rename mechanism.

### Magisk: hiding is more than changing applicationId

The [core manifest][magisk-manifest] specifies regular services without a fixed
private process suffix. The [stub manifest][magisk-stub-manifest] is a template;
it is insufficient to inspect it alone. [ManifestUpdater][magisk-stub-build]
generates placeholder component entries, and [AppMigration.patchAndHide][magisk-migration]
uses that stub, generates a random package when none is supplied, replaces the
original package in manifest strings, and randomizes placeholder component names.

Consequently neither the original package nor the core service class names are
established as persistent nice-name identifiers in the hidden installed app.
Random-name length/case/structure is not a Magisk-unique signature. Historical
default-package residue, if present, is a separate existing signal and does not
validate detection of the hidden app's later requests.

## Niceness is a separate subsystem

`--nice-name` is a string. Numeric priority is exposed through [Process JNI][process-native].
[Native zygote][zygote-native] changes fork priority and resets it in specialization.
[ACK set_one_prio][ack-priority] checks ownership, permission to reduce nice and
the LSM; [can_nice][ack-scheduler] accounts for `RLIMIT_NICE` or `CAP_SYS_NICE`.
None establishes a family-specific historical naming signal. This ACK commit
is not a claim that every Android 16 device runs kernel 6.12. Architecture and
vendor-specific probes are unnecessary for this name-only research.

## Evidence model and the spoofing limit

Even an exact, structurally valid parameter in a real Java String can be created
by ordinary application code. Confirming String/value linkage rejects arbitrary
arrays and metadata; it does not establish that zygote produced the String.
Object linkage, if later added, still does not authenticate request provenance.

For #363, distinguish two acceptance requirements:

- Reject substrings, detached arrays, malformed records and unsupported layouts
  as eligible parameter evidence.
- A byte-identical, well-formed spoof has the same string observation. It cannot
  be rejected by a content-only classifier while the genuine string is accepted.
  Report an unauthenticated weak candidate, or keep the rule disabled; never
  claim that structural validation solves authentic-origin spoofing.

One String or several fields from one naming/request mechanism must not increase
confidence through double counting. Adjacent objects and a common package key
do not establish the same request. Neither positive nor negative results certify
installation, successful startup, root access, current credentials, or safety.

## Proposed boundary if later experiments justify a rule

Ownership stays in `heapresidue`. Within its existing single bounded scan, parse
an anchored complete nice-name argument into bounded package/suffix tokens;
dispatch exact local rule IDs without enumerating benign names. Keep only a
bounded set of matched rule IDs and minimal summaries. A shared suffix yields
one ambiguous family group, not separate KernelSU and APatch findings.

Expose `weak candidate observed`, `not observed in this snapshot`, `inconclusive`,
`unavailable` and `unsupported` distinctly. Version/layout/transport failures and
resource limits cannot become negative results. No new JNI, dump, permission,
root invocation, upload, export or cross-feature implementation dependency is
needed. The current raw-heap retention restrictions continue to apply.

This is a conditional design, not implemented runtime behavior. A rule needs the
[experiment gates](EXPERIMENTS.md), source review and measured incremental
coverage before its data/domain/presentation contracts are added.

## Completed and missing validation

The new `NiceNameResearchBoundaryTest` runs binary fixtures through the existing
scanner: original versus renamed names, class suffixes, generic AppZygote names,
synthetic exact-name acceptance, and detached-array rejection. Identifier widths
and String encodings are exercised for the rename comparison. These controls
establish scanner behavior, not Android execution or exploit effectiveness.

Local results: `:feature:heapresidue:data:testDebugUnitTest` passed all 27 tests
(including five new research controls); the source-audit tool's seven tests
passed. A fresh network fetch and subsequent offline verification passed for all
29 pinned files (the first network attempt timed out; the full retry passed).
Repository evidence,
source-length, detector-touch-point, reflection, text-protocol, JNI and native
boundary checks passed, as did `git diff --check`. No runtime implementation or
public API changed; app assembly and real-device smoke tests were not run for
this research/test-only change.

On 2026-10-09, `adb devices -l` returned no connected devices. No manager rename,
receiver activation, AppZygote route, GC window, OEM coverage, real heap benchmark
or scheduling experiment was performed. No hit rate, false-positive rate or
performance improvement is claimed. Device work remains explicitly open under #363.

## Source links

[service-doc]: https://developer.android.com/guide/topics/manifest/service-element
[receiver-doc]: https://developer.android.com/guide/topics/manifest/receiver-element
[context-doc]: https://developer.android.com/reference/android/content/Context#bindIsolatedService(android.content.Intent,int,java.lang.String,java.util.concurrent.Executor,android.content.ServiceConnection)
[namespace-doc]: https://developer.android.com/build/configure-app-module
[priority-doc]: https://developer.android.com/reference/android/os/Process#setThreadPriority(int)
[zygote-process]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/android/os/ZygoteProcess.java
[zygote-arguments]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/com/android/internal/os/ZygoteArguments.java
[zygote-connection]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/com/android/internal/os/ZygoteConnection.java
[zygote]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/com/android/internal/os/Zygote.java
[active-services]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/services/core/java/com/android/server/am/ActiveServices.java
[process-list]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/services/core/java/com/android/server/am/ProcessList.java
[app-zygote]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/android/os/AppZygote.java
[zygote-native]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/jni/com_android_internal_os_Zygote.cpp
[process-native]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/jni/android_util_Process.cpp
[art-hprof]: https://android.googlesource.com/platform/art/+/ba2c65bbab5a55e204b32d7b1480011a1bcb57f9/runtime/hprof/hprof.cc
[ack-priority]: https://android.googlesource.com/kernel/common/+/e65d894191a4f781c98ca3fe40d147d058483419/kernel/sys.c
[ack-scheduler]: https://android.googlesource.com/kernel/common/+/e65d894191a4f781c98ca3fe40d147d058483419/kernel/sched/syscalls.c
[ksu-manifest]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/AndroidManifest.xml
[ksu-build]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/build.gradle.kts
[ksu-boot]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/magica/BootCompletedReceiver.java
[ksu-service]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/magica/MagicaService.java
[ksu-preload]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/magica/AppZygotePreload.java
[apatch-manifest]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/AndroidManifest.xml
[apatch-build]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/build.gradle.kts
[apatch-boot]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/java/me/bmax/apatch/magica/BootCompletedReceiver.java
[apatch-service]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/java/me/bmax/apatch/magica/MagicaService.java
[apatch-preload]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/java/me/bmax/apatch/magica/AppZygotePreload.java
[ksu-settings]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/data/repository/SettingsRepositoryImpl.kt
[ksu-home]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/ui/screen/home/HomeScreen.kt
[apatch-cli]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/java/me/bmax/apatch/util/APatchCli.kt
[magisk-manifest]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/core/src/main/AndroidManifest.xml
[magisk-migration]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/core/src/main/java/com/topjohnwu/magisk/core/tasks/AppMigration.kt
[magisk-stub-build]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/build-logic/src/main/java/Stub.kt
[magisk-stub-manifest]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/stub/src/main/AndroidManifest.xml
