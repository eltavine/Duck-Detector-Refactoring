# Duck Detector module architecture

Duck Detector uses ports-and-adapters boundaries. Probes, meaning Android framework calls, Binder, KeyStore, JNI and native code, live only in the data modules of features and capabilities, on top of the platform access `:core:platform` shares. The two composition roots, `:sdk:runtime` and `:app`, wire them together and own the process entry points, and a detector layer only hands an Android `Context` to its data layer's scanner. The evidence, native payload, report and scan contracts, every domain layer and every presentation layer are pure JVM modules without the Android framework.

To add a detector, follow [Adding a detector](../guides/adding-a-detector.md). To run the detectors inside another application, see [Using the SDK](../guides/sdk-integration.md).

## Module dependency direction

```text
:app -> :sdk:<unit> -> :feature:<unit>:<layer> -> :capability:<unit>:<layer> -> :core:<unit>

inside one feature unit:     data -> domain
                             presentation -> domain
                             detector -> data + presentation + domain
                             ui -> detector + presentation + domain
inside one capability unit:  data -> domain

:core:report, :core:scan -> :core:evidence
:core:detector -> :core:evidence + :core:report
:core:ui -> :core:designsystem + :core:evidence + :core:report + :core:scan
```

Arrows point from a module to the modules it may depend on. Feature units never depend on other feature units, capability units never depend on other capability units, nothing depends on `:app`, pure JVM modules depend neither on Android modules nor on Android artifacts, and only UI modules may use Compose. [`module-boundaries.json`](../../.github/policies/module-boundaries.json) states each layer's rule once as a template and lists only the core modules and `:app` individually. Settings include every module by discovering its directory, so a new unit needs no central entry.

| Module | Responsibility | Forbidden knowledge |
|---|---|---|
| `:core:evidence` | `DetectorId`, `DetectorStatus`, `DetectionSeverity`, and `ContractValue`, which marks the SDK contract's value types for Poko | Android, reports, scans, UI |
| `:core:native` | Native library handle, payload codec, the disposable child runner and the seccomp-trap exit that forked probe children use, and snapshot collection status shared by every JNI bridge | Android, detector semantics, specific native units |
| `:core:platform` | Android platform access every probe shares: reflection-free failure names, hidden platform failure identity, the hidden `SystemProperties` and `ServiceManager` access, and the gate every app zygote carrier starts through | Detector semantics, verdicts, UI |
| `:core:report` | Typed export model: `DetectorReport`, `DeviceReport`, rows, facts and blocks; `DetectorHeadline`, which every card model states; `DetectorResult` | Android, rendering, specific detectors |
| `:core:scan` | `DetectorSummary`, `ScanSessionRunner` (per-detector scan lifecycle), `ScanCoordinator` (dashboard-wide progress and timing) | Android, UI, specific detectors |
| `:core:detector` | The headless detector contract: `Detector` (identity, scanner, loading report, card model, export, consents and app zygote work), `DetectorConsent`, `DetectorSpecificApi`, the opt-in marker that keeps each detector's typed object outside the stable contract, the `DetectorScanner` port and `run`, which returns a `DetectorResult` without any UI | Compose, specific detectors, probes |
| `:core:designsystem` | The visual language every UI module shares: `DuckDetectorTheme` with its monochrome color scheme, whose accents invert with the theme, typography, the grouped palette and its status colors, shapes with continuous corners from AndroidX graphics-shapes, motion tokens, button colors and the status bar protection of edge-to-edge screens | Detectors, evidence, reports, scans, strings |
| `:core:ui` | Card frames and shared Compose components built on `:core:designsystem`, shared strings, the `DetectorFeature` / `DetectorSession` and device profile contract the composition root works with, `ConsentCard`, which shows a detector's consent, and `CardDetectorFeature`, the one session and view model every standard card shares | Detector rules, probes, specific detectors |
| `:capability:<unit>:domain` | Evidence types a capability shares with several features | Android, feature interpretation, UI |
| `:capability:<unit>:data` | Collection of shared evidence: package inventory, early preload capture, system property reads, helper processes, SELinux policy carriers, attestation | Feature verdicts, presentation, other capabilities |
| `:feature:<unit>:domain` | The feature's result and report models and pure judgement rules | Android, JNI, UI, other features |
| `:feature:<unit>:data` | Probes, repositories, JNI bridges, platform access and the feature's services | Presentation, UI, other features |
| `:feature:<unit>:presentation` | The card model, which states its `DetectorHeadline`; the mapper from the domain report; and the `DetectorReport` projection | Android, probes, JNI, other features |
| `:feature:<unit>:detector` | The detector's one headless object, `<Name>Detector`: binds the data scanner, the domain loading report and the presentation mapping and export; used by the SDK and the ui layer | Compose, probes beyond creating the scanner, other features |
| `:feature:<unit>:ui` | The internal Compose card and dialogs, and one public `DetectorFeature`, `detectorFeature`, built with `CardDetectorFeature`; among the detectors, only TEE keeps its own view model, for its expansion and dialog state | Probes, JNI, other features' models |
| `:feature:dashboard:*` | Card ordering, overview, findings and export rendering over `DetectorSession` lists | Any specific detector |
| `:feature:settings:*`, `:feature:update:*`, `:feature:deviceinfo:*` | Supporting features with the same layering | Detector internals |
| `:sdk:runtime` | The headless composition root: `DetectorCatalog`, the one list of detectors in scan-start order; `DuckDetector`, which runs them without any UI and reports the process's package visibility; the native libraries; and the process-level hooks: `DuckDetectorZygotePreload`, which its manifest names, launch evidence capture and the mount-view sampler | Compose, UI modules, per-detector branching |
| `:sdk:aar` | The distributable: fuses `:sdk:runtime` and every headless module it is made of into one AAR with its native libraries and services; `verifySdkAar` fails when a project module is left unfused or a UI library reaches it | Code of its own |
| `:app` | The UI composition root: activities, the dashboard cards, generated from every detector's ui layer, notifications, startup policy with the detectors' consents, and package visibility, which it reads through the SDK; it declares the early capture launcher and calls the SDK's launch hooks | Detection rules, probes, report semantics, per-detector branching |

### Capabilities and their consumers

| Capability | Shared evidence | Consumers |
|---|---|---|
| `attestation` | KeyStore attestation collection, extension parsing, trust roots, boot consistency | bootloader, tee |
| `earlypreload` | Mount and virtualization evidence captured by the transparent `NativeActivity` before the activity it launches | mount, virtualization |
| `helperprocess` | Isolated and helper process services, remote snapshots, dex path and UID identity collectors | mount, nativeroot, virtualization |
| `packageinventory` | Installed package inventory and visibility checks | customrom, dangerousapps, lsposed, nativeroot, virtualization |
| `selinuxpolicy` | SELinux context validity carriers, proc attr and policyload seqno probes, dirty policy preload queries | lsposed, selinux |
| `systemproperties` | Multi-source system property reads, native property snapshots, and the native parser of bionic's property areas | adbruntime, bootloader, systemproperties; customrom's native unit uses the property area parser |

A capability collects; each consumer interprets. A capability exists only because at least two features consume the same evidence.

## Build logic

Convention plugins in `build-logic` configure every module, so a module's build file names its layer's plugin and its dependencies and nothing more.

| Plugin | Configures |
|---|---|
| `duckdetector.jvm.library`, `duckdetector.android.library` | Java 17 bytecode, the module boundary policy, dependency analysis, and Kotlin language and API version 2.3 with the 2.3 standard library (`duckdetector.kotlin.sdkStdlib`), so the fused SDK compiles in hosts on Kotlin 2.2 or later |
| `duckdetector.android.application` | The app, with the generated dashboard cards and the committed assets: the GitHub contributor list and TEE's revocation list snapshot, whose refresh tasks share one `java.net.http` client and retry policy |
| `duckdetector.android.compose` | Compose, for ui modules |
| `duckdetector.android.apk-artifacts` | APK file names that carry the build's commit |
| `duckdetector.contract-values` | Poko, which generates `equals`, `hashCode` and `toString` for the `@ContractValue` classes of the SDK contract modules |
| `duckdetector.public-api` | `checkPublicApi` and `updatePublicApi`, over Kotlin's ABI tools |
| `duckdetector.dependency-analysis` | `buildHealth`, from the Dependency Analysis Gradle Plugin |
| `duckdetector.module-boundaries` | The module boundary policy, checked while the build configures |
| `duckdetector.sdk.distribution` | The fused SDK AAR, its Maven publication and `verifySdkAar` |

The Android conventions opt the modules that compose detectors, the detector and ui layers, `:sdk:runtime` and `:app`, in to `DetectorSpecificApi`. In any other module, the compiler rejects the use of a detector's typed object.

## Enforcement

| Guard | Enforces | Self-test |
|---|---|---|
| `DuckDetectorModuleBoundariesPlugin` with `module-boundaries.json` | Classification by layer template or member entry, plugin kind, allowed project dependencies, direction, isolation, JVM purity, UI isolation (Compose only in UI modules) and acyclicity; evaluated while configuring every build | `./gradlew :build-logic:test` |
| `check-native-boundaries.py` with `native-boundaries.json` | Every native file belongs to one unit and lives in the module that owns it, include direction, per-unit CMake targets and their registration, JNI exports owned by the unit's module | `test-native-boundaries.py` |
| `check-detector-touch-points.py` with `detector-touch-points.json` | Outside `feature/<name>/`, a detector is named only by `DetectorCatalog`, which must name every detector, by tooling indexes, and by reviewed exceptions that state a reason | `test-detector-touch-points.py` |
| `check-jni-contracts.py` | Every Kotlin `external` declaration has exactly one C++ definition with C linkage and `JNIEXPORT`, and vice versa | `test-jni-contracts.py` |
| `check-reflection-boundaries.py` with `reflection-allowlist.json` | Kotlin and Java code uses reflection only in reviewed files, each naming its reason: member lookups, reflective class loading, proxies and hidden API access only where a probe needs a hidden platform API, and runtime class names only where that identity is itself the evidence. Report wording never comes from a class name | `test-reflection-boundaries.py` |
| `check-source-file-length.py` | No source file reaches 400 lines | `test-source-file-length.py` |
| `check-text-protocols.py` with `text-protocols.json` | Presentation, ui, core, SDK, app and native code decide from typed values, never by comparing, searching or stripping text another layer or unit wrote; reviewed files that read text by nature state a reason | `test-text-protocols.py`; `scripts/test_new_detector.py` runs it on a scaffolded detector |
| `check-evidence-records.py` | Every detector and capability keeps an `EVIDENCE.md` whose signal entries fill every AGENTS.md §12 field, cite a primary source or declare `Discovery only:`, and are not drafts | `test-evidence-records.py`; `scripts/test_new_detector.py` checks the scaffold writes a draft CI rejects |
| `./gradlew buildHealth` (`DuckDetectorDependencyAnalysisPlugin`) | Every module declares exactly the modules and libraries its code uses: nothing unused, nothing reached only transitively, and `api` only for types in its public API. The plugin records its two reviewed exceptions | Upstream Dependency Analysis Gradle Plugin |
| `:sdk:aar:verifySdkAar` | The SDK AAR fuses every project module it needs and reaches no UI library, directly or through an external dependency | Runs on the Fused Library report |
| `checkPublicApi` (`DuckDetectorPublicApiPlugin`) | The public API of the SDK contract modules, `:sdk:runtime`, `:core:detector`, `:core:report` and `:core:evidence`, matches the dump committed in each module's `api/`; `updatePublicApi` records an intended change. The dumps come from Kotlin's ABI tools, in the Kotlin Gradle plugin's format | `ApiClassFilesTest`; the ABI tools are Kotlin's own |
| `scripts/new_detector.py` | A generated detector builds and passes every guard, and changes nothing outside `feature/<name>/` except its registrations | `scripts/test_new_detector.py`; CI also scaffolds a native detector and builds it |
| `DashboardExportGoldenTest` | The export of every detector recorded in `golden-detectors.txt` stays byte-identical | Golden fixtures in `app/src/test/.../integration/dashboard` |

The CI `contracts` job runs the Python checkers and their self-tests. The `verify` job runs `:build-logic:test`, every module's `unitTest`, `checkPublicApi`, `:app:assembleDebug` for all four ABIs, `buildHealth`, `:sdk:aar:publish` with `:sdk:aar:verifySdkAar`, the sample application built from the published AAR alone, and `:app:lintDebug`, which analyses every dependency of `:app`. It ends by scaffolding a native detector in the checkout, checking which files changed, and building and testing the result.

## Composition invariants

`DetectorCatalog` in `:sdk:runtime` is the one list of detectors and fixes the order their scans start. `DetectorFeatures` in `:app` orders the dashboard cards by the catalog. The cards come from `detectorCards`, which `GenerateDetectorCardsTask` writes from the `detectorFeature` every `feature/<name>/ui` module exports, so listing the cards names no detector. A unit test fails when a detector has no card or a card has no detector. The shell starts one session per card in that order, and the scan coordinator, dashboard and export list the sessions by detector id. Dashboard, export and notification code receive `DetectorSession` lists and typed models. They never enumerate detectors, reflect over detector types, or match presentation text.

Consents follow the same path. A detector lists the user decisions it needs in `Detector.consents`, and its ui module describes each one in `DetectorFeature.consentCards`. The startup policy screen shows one card per consent, and settings shows one switch per consent. A change calls `decide` and rescans the session of the detector that owns the consent, so neither screen names a detector.

Process hooks need no entry either. A detector with app zygote work overrides `Detector.appZygotePreload`, which `DuckDetectorZygotePreload` runs in catalog order. The SDK's manifest names that preload, and each module's manifest declares the services and intent filters its probes need, so neither the app nor an SDK host declares anything for a detector.

Scan lifecycle is owned explicitly:

```text
rescan request -> publish loading state -> wait for the previous scan of the same detector
-> skip if a newer request arrived -> collect -> publish only if still the newest request
```

`ScanSessionRunner` serializes the scans of one detector and suppresses stale results. `ScanCoordinator` observes every published `DetectorSummary` and owns dashboard-wide progress, session identity and timing through a `ScanClock` port.

## Native units

Native code is split into units. Each unit lives in the module that owns it, as `<module>/src/main/cpp/<unit>/`, with a `CMakeLists.txt` listing its sources, so a detector's C++ sits next to its Kotlin JNI bridge. The `DUCKDETECTOR_NATIVE_UNITS` registry in `sdk/runtime/src/main/cpp/CMakeLists.txt` names every unit with its owner, in link order, and links each `duckdetector_<unit>` object library into `libduckdetector.so`. `mount/zygotenext` is the exception: it builds the standalone `libmain.so` that `zygote_next` loads without ART.

| Unit | Owner | May include |
|---|---|---|
| `common` | `:core:native` | - |
| `tee` (including `tee/asm/<abi>`) | `:feature:tee:data` | `common` |
| `virtualization` (including `virtualization/asm/arm64`) | `:capability:helperprocess:data` | `common` |
| `preload` | `:capability:earlypreload:data` | `common`, plus `virtualization/snapshot_builder.h` by recorded exception |
| `selinuxpolicy` | `:capability:selinuxpolicy:data` | `common` |
| `packageinventory`, `systemproperties` | the capability of the same name | `common` |
| `zygotenext` (`mount/zygotenext`) | `:feature:mount:data` | `common` |
| `customrom` | `:feature:customrom:data` | `common`, plus the `systemproperties` property area parser (`prop_area_file.h`, `prop_area_format.h`, `prop_area_parser.h`) by recorded exception |
| every other directory | `:feature:<directory>:data` | `common` |

## Extension rules

1. Create a detector with `scripts/new_detector.py`, as `:feature:<name>:{domain,data,presentation,detector,ui}` with one entry in `DetectorCatalog` ([guide](../guides/adding-a-detector.md)). Settings, the boundary policy, both composition roots, the app's list of dashboard cards and the SDK AAR pick up the new modules from their directories. Central code must not change.
2. Put judgement rules in the feature's domain layer and keep them pure JVM; the data layer collects and the presentation layer projects.
3. Share evidence acquisition only through a capability used by at least two features. The capability must not interpret the evidence for any of them.
4. Never add a dependency between two feature units or two capability units. If they need the same evidence, extract a capability; if they need the same contract, it belongs in `:core`.
5. Decide from typed values. A layer or native unit never compares, searches or strips text another one wrote; carry an enum, id or flag from where the evidence is produced. A data layer may read the platform's text, such as an error message, and turns it into types there. Export and dashboard output change only through a feature's own `DetectorReport` projection. Update the golden fixtures deliberately, never to silence a diff. A new detector does not have to join them; regenerating them records every catalogued detector.
6. Add native code as `src/main/cpp/<unit>/` in the module that owns it, with a `CMakeLists.txt` that declares its `duckdetector_native_unit` target, one line in the `DUCKDETECTOR_NATIVE_UNITS` registry and a `native-boundaries.json` entry. Cross-unit includes need a header-level exception with a reason.
7. Keep JNI bridges inside the module that owns the native unit. Kotlin `external` functions must be public or private members of a class or object other than a companion object, and must not be overloaded.
8. Keep `:app` a composition root. It may wire adapters and platform entry points but must not acquire detection rules or per-detector branching. Manifest entries a probe needs belong in the manifest of the module that owns the probe.
9. Split any file that approaches 400 lines along semantic ownership; there is no baseline to hide in. When splitting native timing code, keep each measured path, the timer reads and the calls between them, in one translation unit.
10. Record every deliberate boundary exception in [follow-ups](./follow-ups.md), together with the reason it is still needed.
