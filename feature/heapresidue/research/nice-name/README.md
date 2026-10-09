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
  Its boot-time launch may be parsed by a USAP, and the audited source does not
  guarantee that it reaches the heap the collector inherits.
- Reject `_zygote` by itself as a root-family discriminator. Separately,
  `<policy package>_zygote` is an experiment-only exact-name candidate for
  unrenamed managers: the platform zygote always parses AppZygote startup in Java,
  but its prefix follows the installed package, so it cannot recover a renamed
  manager.
- Do not promote `MagicaService` class names into the collector's rules. Their
  requests are parsed by the app's AppZygote, a child of the platform zygote, so
  they cannot enter the heap the collector inherits.
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
require a new audit. `sources.json` pins 40 source files with SHA-256 and review
anchors, and five repository-wide searches with their exact expected file sets.
It contains no copied upstream implementation or device data.

From the repository root (searches also need `git`):

```sh
python3 feature/heapresidue/research/nice-name/audit_sources.py --fetch --cache-dir /tmp/duck-363-source-cache
python3 feature/heapresidue/research/nice-name/audit_sources.py --cache-dir /tmp/duck-363-source-cache
python3 -m unittest discover -s feature/heapresidue/research/nice-name -p 'test_*.py'
./gradlew :feature:heapresidue:data:testDebugUnitTest
```

The first command explicitly downloads public files and shallow commits; the
second is offline. The tool verifies inputs, prints anchor line numbers, and fails
when a search matches any file set other than the recorded one. A commit ID
authenticates the searched tree, but a search bounds one text pattern: it does not
exclude obfuscated, generated, external or downstream code. The tool does not
validate the conclusions, execute upstream code, open a device, or analyze a raw
heap. Human review of the located control flow remains necessary. CI runs the
tool's offline self-tests, not the network audit.

Public API semantics were checked against Android's [service manifest][service-doc],
[receiver manifest][receiver-doc], [isolated binding][context-doc],
[application ID / namespace][namespace-doc], and [thread priority][priority-doc]
documentation. Web documentation is not revision-pinned; the implementation
claims below use immutable source. Existing transport, GC and SELinux limits
remain in [EVIDENCE.md](../../EVIDENCE.md) and are not redefined by this study.

## Parameter production and ownership

1. A manifest's `android:process` selects the component's process. A name that
   starts with `:` becomes the declaring package plus that suffix; any other name
   is used verbatim when it is a dotted identifier, which cannot contain `:`
   ([ComponentParseUtils.buildCompoundName][component-parse-utils],
   [validateName][framework-parsing-utils]). [ProcessList][process-list] looks
   processes up by name and UID, so another app's process may carry the same name.
   The resolved installed manifest matters, not the source manifest alone.
   Application ID, namespace and component names can change independently;
   inspect the built APK for every renamed sample.
2. [ActiveServices.getProcessNameForService][active-services] uses the resolved
   service process for regular services. For ordinary isolated services it adds
   the component class name. Custom instance binding first appends the instance
   to that class name; shared-isolated, package-isolated and SDK sandbox branches
   differ. Therefore a class name is not universally a process name.
3. [ProcessList.startProcess][process-list] routes ordinary processes through
   `Process.start`, but AppZygote-backed children through `appZygote.startProcess`.
   [ActiveServices.bringUpServiceLocked][active-services] selects the latter from
   `FLAG_USE_APP_ZYGOTE`.
4. [AppZygote.connectToZygoteIfNeededLocked][app-zygote] asks the platform zygote
   (`Process.ZYGOTE_PROCESS`, primary or secondary by ABI) to start `AppZygoteInit`
   with the application's process name plus `_zygote`. This is a separate request
   from the isolated service child's request.
   [ZygoteProcess.startChildZygote][zygote-process] uses a generic entry-point/UUID
   socket name and supplies neither a package-name argument nor an app-data-dir
   argument, so neither can be assumed to accompany its nice name as an identity
   tuple. [ProcessList][process-list] reuses a running AppZygote per process name
   and UID and kills it after a delay once unused: one startup request can serve
   many service launches.
5. [ZygoteProcess.startViaZygote][zygote-process] serializes the supplied name into
   `--nice-name`; [ZygoteArguments.parseArgs][zygote-arguments] stores its assigned
   value in `mNiceName`. The value field does not contain the parameter prefix.
6. [ART HPROF][art-hprof] serializes Java Strings through instance records and
   synthetic primitive value arrays. It does not authenticate their producer,
   certify process start success, or provide a trusted startup-event timestamp.

## Which process parses a request

The collector inherits only objects that the zygote of its own ABI allocated and
still held when it forked the collector. Source establishes where a request is
parsed; it does not establish that the object survives:

- [ZygoteProcess][zygote-process] offers a request to a USAP only when its policy
  is latency-sensitive and not a system process and no argument is
  USAP-incompatible; `--start-child-zygote` is incompatible. A USAP parses the
  arguments in its own heap ([Zygote.childMain][zygote]).
- Service launches request `ZYGOTE_POLICY_FLAG_EMPTY`
  ([ActiveServices.bringUpServiceLocked][active-services]), which
  [ActivityManagerService][activity-manager] and [ProcessList][process-list] pass
  unchanged, so they are not USAP-eligible. This includes DuckDetector's own
  collector: at this revision it is forked on request rather than taken from a
  pool. [EVIDENCE.md](../../EVIDENCE.md) keeps its USAP caveat until ancestry is
  measured on devices.
- Receiver cold starts are latency-sensitive only when the broadcast carries a
  temporary allowlist ([BroadcastQueueImpl][broadcast-queue]).
  [UserController][user-controller] attaches one to `LOCKED_BOOT_COMPLETED` and
  `BOOT_COMPLETED`, so a boot-time receiver launch may be parsed by a USAP when
  the pool is enabled.
- [ZygoteConnection.processCommand][zygote-connection] parses a command in Java
  before forking it. When the USAP pool is disabled and indefinite thread
  suspension is safe ([ZygoteServer][zygote-server]), a command from
  system_server is then forked by a native loop that also forks the following
  simple commands without returning to Java. That loop copies the nice name into
  a fixed native buffer and allocates no Java String in the zygote
  ([native command buffer][zygote-command-buffer]); each child re-parses its own
  command after the fork. Child-zygote requests take neither the USAP nor the
  native path.
- An AppZygote parses its children's requests; it is a child of the platform
  zygote, never an ancestor of the collector.

Thus only an AppZygote startup request is guaranteed by source to become a Java
String in the platform zygote. Any other name additionally needs the Java path,
the collector's ABI, and survival until the dump; none of these is measured here.
A collector's own startup arguments do not demonstrate residue of another
application's launch.

## Candidate ledger

| Candidate | Producer and trigger | Parsed by | Rename behavior / identity | Decision |
| --- | --- | --- | --- | --- |
| `<resolved package>:magica_boot` | KernelSU/APatch boot receiver, if enabled and dispatched; not an isolated service | Platform zygote (Java or native path), or a USAP for boot broadcasts when the pool is enabled | A package-only rename can preserve the literal suffix; shared across families and reproducible by any app's own private process | Experiment-only candidate; no root finding |
| `<application process>_zygote` | Framework startup of an AppZygote when a service needs one and none is running | Platform zygote, always in Java | Prefix follows the installed application process; the suffix is generic Android behavior | Reject as family rule; `<policy package>_zygote` stays an experiment-only exact-name candidate |
| `<service process>:me.weishu.kernelsu.magica.MagicaService` or APatch equivalent | Framework request to the app's own AppZygote; service class as resolved in the installed APK | That AppZygote | Class may survive an applicationId-only change, but component rewriting can remove it | Cannot reach the collector's inherited heap; no rule |
| Hidden Magisk package or component name | Repacked stub's installed manifest | Platform zygote or USAP, by launch type | Package and placeholder components are randomized in the audited transformation | No stable nice-name candidate established |
| Negative/nondefault numeric nice | Scheduler state, not naming | Not a startup argument | Legitimate changes and permission/limit conditions exist | Reject as independent root rule |

### KernelSU: the boot and direct-service routes are distinct

The [manifest][ksu-manifest] gives the receiver `:magica_boot`, disables it by
default, and declares [`MagicaService`][ksu-service] isolated with AppZygote
enabled. The receiver is not exported and is `directBootAware`. Besides
`LOCKED_BOOT_COMPLETED` and `BOOT_COMPLETED`, it accepts a hard-coded
`me.weishu.kernelsu.magica.LAUNCH` action whose string does not follow the
application ID; without export only the system, the app itself or same-UID apps
can deliver it ([receiver manifest][receiver-doc]). The [settings
implementation][ksu-settings] enables the receiver through the optional
`autoJailbreak` setting, which defaults to false. The `ksu-boot-receiver-references`
search finds no other file naming the receiver, its process or its action. The
[receiver][ksu-boot] returns before starting the service when `rootAvailable()`
succeeds.

That check occurs **inside onReceive**, after the receiver process was selected.
It cannot imply that a `:magica_boot` name means root was unavailable or that
successful root prevents the receiver name from appearing. When enabled, this
route fires at boot, so a later scan also depends on survival since boot, for
which [EVIDENCE.md](../../EVIDENCE.md) establishes no guarantee.

The [home action][ksu-home] starts `MagicaService` directly; it does not require a
`:magica_boot` receiver launch. Thus a manager or its service can run while this
suffix is absent. The [preload callback][ksu-preload] runs in AppZygote and passes
application information to native code; class/log/library strings loaded there
must not be presumed present in the platform zygote's heap.

The [build configuration][ksu-build] accepts `KSU_PACKAGE_NAME` while keeping a
fixed namespace, and PR builds default to `me.weishu.kernelsu.pr`. The kernel
compiles the same option ([Kbuild][ksu-kbuild]) and only crowns an installed
manager whose package equals it ([throne_tracker.c][ksu-throne-tracker]). A
renamed manager therefore pairs with a matching custom kernel or module build; it
is not a transformation applied to an existing installation. The `.pr` default is
absent from the current exact-name policy; adding it is a separate policy change.
Preservation of final component names must still be checked in the merged/release
manifest; this audit did not build a renamed manager APK.

### APatch: shared suffix, different activation evidence

The [manifest][apatch-manifest] has the same disabled, `directBootAware`
`:magica_boot` receiver and the same isolated AppZygote
[`MagicaService`][apatch-service]. Its receiver is exported in this baseline,
unlike KernelSU's, and accepts a hard-coded `me.bmax.apatch.magica.LAUNCH`
action. The [receiver][apatch-boot] similarly checks root availability after
process selection. The [installJailbreak route][apatch-cli] starts the service
directly.

The `apatch-boot-receiver-references` search finds the receiver, its process and
its action only in the manifest and the receiver: no tracked file at the pinned
commit enables the component or names the action elsewhere. This does not exclude
obfuscated, external or downstream activation. Do not infer stable boot coverage
from a disabled manifest entry. Because the receiver is exported, any app could
deliver an explicit `me.bmax.apatch.magica.LAUNCH` broadcast once the receiver is
enabled, and the receiver starts the jailbreak chain when root is unavailable.
DuckDetector and its research harness must never send it.

The [preload][apatch-preload] belongs to AppZygote. The [build file][apatch-build]
defines only a namespace, and the `apatch-application-id` search finds no
applicationId assignment, so the application ID is the namespace
([application ID / namespace][namespace-doc]). APatch has no upstream rename
mechanism at this revision; an applicationId-only variant is a lab modification,
not a supported upstream transformation.

### Magisk: hiding is more than changing applicationId

The [core manifest][magisk-manifest] specifies regular services without a fixed
private process suffix, and the `magisk-component-processes` search finds no
`android:process` in any tracked file. The [stub manifest][magisk-stub-manifest]
is a template; it is insufficient to inspect it alone.
[ManifestUpdater][magisk-stub-build] generates placeholder component entries, and
[AppMigration.patchAndHide][magisk-migration] uses that stub, generates a random
package when none is supplied, replaces the original package in manifest strings,
and randomizes placeholder component names. The `magisk-hide-callers` search
finds three callers: the [home-screen dialog][magisk-home] and `AppMigration.hide`
supply no package; only the upstream [instrumentation test][magisk-test-environment]
supplies `repackaged.com.topjohnwu.magisk`.

Consequently every hidden component runs in the random package's default process,
and neither the original package nor the core service class names are established
as persistent nice-name identifiers in the hidden installed app. Random-name
length/case/structure is not a Magisk-unique signature. Historical default-package
residue, if present, is a separate existing signal and does not validate detection
of the hidden app's later requests.

## Niceness is a separate subsystem

`--nice-name` is a string. Numeric priority is exposed through [Process JNI][process-native].
[Native zygote][zygote-native] changes fork priority and resets it in specialization.
[ACK set_one_prio][ack-priority] checks ownership, permission to reduce nice and
the LSM; [can_nice][ack-scheduler] accounts for `RLIMIT_NICE` or `CAP_SYS_NICE`.
None establishes a family-specific historical naming signal. This ACK commit
is not a claim that every Android 16 device runs kernel 6.12. Architecture and
vendor-specific probes are unnecessary for this name-only research.

## Evidence model and the spoofing limit

A structurally valid parameter in a real Java String does not identify its
producer:

- Another app chooses its own process names. A private name yields
  `<its package>:<suffix>`, so any app can produce `<its package>:magica_boot`.
  A global name may equal a policy package, so any app can cause a genuine zygote
  request carrying `--nice-name=me.weishu.kernelsu` while its `--package-name`
  differs. The existing NICE_NAME argument cannot distinguish such a launch.
- Code running in the collector process itself, including an SDK host's
  Application or providers (see [EVIDENCE.md](../../EVIDENCE.md)), can allocate
  an identical String.
- A modified zygote or runtime can forge or erase strings.

Confirming String/value linkage rejects arbitrary arrays and metadata; it
addresses none of these. Object linkage, if later added, still does not
authenticate request provenance.

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
one ambiguous family group, not separate KernelSU and APatch findings. A
`<policy package>_zygote` extension would strip only that exact suffix before the
existing exact-name lookup and carry the same weak NICE_NAME semantics.

Expose `weak candidate observed`, `not observed in this snapshot`, `inconclusive`,
`unavailable` and `unsupported` distinctly. Version/layout/transport failures and
resource limits cannot become negative results. No new JNI, dump, permission,
root invocation, upload, export or cross-feature implementation dependency is
needed. The current raw-heap retention restrictions continue to apply.

This is a conditional design, not implemented runtime behavior. A rule needs the
[experiment gates](EXPERIMENTS.md), source review and measured incremental
coverage before its data/domain/presentation contracts are added.

## Completed and missing validation

The `NiceNameResearchBoundaryTest` runs binary fixtures through the existing
scanner: original versus renamed names, class suffixes, generic AppZygote names,
a benign global process name equal to a policy package, synthetic exact-name
acceptance, and detached-array rejection. Identifier widths and String encodings
are exercised for the rename comparison. These controls establish scanner
behavior, not Android execution or exploit effectiveness.

Local results on 2026-10-09: `:feature:heapresidue:data:testDebugUnitTest`
passed all 28 tests, including six research controls; the source-audit tool's
twelve tests passed. A fresh network fetch and the subsequent offline run
verified all 40 pinned files and five searches. Repository evidence,
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
[zygote-server]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/com/android/internal/os/ZygoteServer.java
[zygote-command-buffer]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/jni/com_android_internal_os_ZygoteCommandBuffer.cpp
[active-services]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/services/core/java/com/android/server/am/ActiveServices.java
[process-list]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/services/core/java/com/android/server/am/ProcessList.java
[activity-manager]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/services/core/java/com/android/server/am/ActivityManagerService.java
[broadcast-queue]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/services/core/java/com/android/server/am/BroadcastQueueImpl.java
[user-controller]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/services/core/java/com/android/server/am/UserController.java
[app-zygote]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/android/os/AppZygote.java
[component-parse-utils]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/com/android/internal/pm/pkg/component/ComponentParseUtils.java
[framework-parsing-utils]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/java/android/content/pm/parsing/FrameworkParsingPackageUtils.java
[zygote-native]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/jni/com_android_internal_os_Zygote.cpp
[process-native]: https://android.googlesource.com/platform/frameworks/base/+/e96ce2b091188de3bf9cf6385e50a4559839d921/core/jni/android_util_Process.cpp
[art-hprof]: https://android.googlesource.com/platform/art/+/ba2c65bbab5a55e204b32d7b1480011a1bcb57f9/runtime/hprof/hprof.cc
[ack-priority]: https://android.googlesource.com/kernel/common/+/e65d894191a4f781c98ca3fe40d147d058483419/kernel/sys.c
[ack-scheduler]: https://android.googlesource.com/kernel/common/+/e65d894191a4f781c98ca3fe40d147d058483419/kernel/sched/syscalls.c
[ksu-manifest]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/AndroidManifest.xml
[ksu-build]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/build.gradle.kts
[ksu-kbuild]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/kernel/Kbuild
[ksu-throne-tracker]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/kernel/manager/throne_tracker.c
[ksu-boot]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/magica/BootCompletedReceiver.java
[ksu-service]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/magica/MagicaService.java
[ksu-preload]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/magica/AppZygotePreload.java
[ksu-settings]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/data/repository/SettingsRepositoryImpl.kt
[ksu-home]: https://github.com/tiann/KernelSU/blob/df03912f70d92ff2aa9762ef82d607033d37e1da/manager/app/src/main/java/me/weishu/kernelsu/ui/screen/home/HomeScreen.kt
[apatch-manifest]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/AndroidManifest.xml
[apatch-build]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/build.gradle.kts
[apatch-boot]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/java/me/bmax/apatch/magica/BootCompletedReceiver.java
[apatch-service]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/java/me/bmax/apatch/magica/MagicaService.java
[apatch-preload]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/java/me/bmax/apatch/magica/AppZygotePreload.java
[apatch-cli]: https://github.com/bmax121/APatch/blob/526003615ce1783b285cd9340643898325e13dfe/app/src/main/java/me/bmax/apatch/util/APatchCli.kt
[magisk-manifest]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/core/src/main/AndroidManifest.xml
[magisk-migration]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/core/src/main/java/com/topjohnwu/magisk/core/tasks/AppMigration.kt
[magisk-home]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/apk/src/main/java/com/topjohnwu/magisk/ui/home/HomeScreen.kt
[magisk-test-environment]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/core/src/main/java/com/topjohnwu/magisk/test/Environment.kt
[magisk-stub-build]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/build-logic/src/main/java/Stub.kt
[magisk-stub-manifest]: https://github.com/topjohnwu/Magisk/blob/b268b361f0d46318986cf50eac62e90c2dbcd235/app/stub/src/main/AndroidManifest.xml
