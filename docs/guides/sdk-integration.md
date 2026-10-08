# Using the Duck Detector SDK

The SDK is Duck Detector without its UI: every detector, the native libraries and the helper services, in one AAR. The app is built from the same modules, so both run the same probes and produce the same reports.

## Build the AAR

```bash
./gradlew :sdk:aar:publish
```

This publishes `com.eltavine.duckdetector:duckdetector-sdk:0.0.0-SNAPSHOT` to `sdk/aar/build/repository`; pass `-Pduckdetector.sdk.version=<version>` for another version. Assembling the AAR runs `verifySdkAar`, which fails if a headless module is missing from it or a UI library reaches it.

The [Nightly release](https://github.com/eltavine/Duck-Detector-Refactoring/releases/tag/nightly) also includes a commit-named SDK AAR alongside the APK. That AAR is the fused library file; use the local Maven publication above when you need its POM to resolve external dependencies.

## Requirements

| Requirement | Value |
|---|---|
| `minSdk` | 29 |
| `compileSdk` | 37 or later, the AAR's `minCompileSdk` |
| Kotlin | 2.2 or later, such as the Kotlin that AGP 9 bundles. The SDK compiles with Kotlin language and API version 2.3 and requires the 2.3 standard library, and a Kotlin compiler reads metadata one version ahead |
| ABIs | `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64` |
| Repositories | The SDK repository, `google()`, `mavenCentral()`, and `https://jitpack.io` for Tencent's `soter-core` |

[`samples/sdk-consumer`](../../samples/sdk-consumer) is a complete application that depends on the published AAR alone, and CI builds it on every pull request.

## Add the dependency

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        maven(url = file("<path to>/sdk/aar/build/repository"))
        google()
        mavenCentral()
        maven(url = "https://jitpack.io")
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.eltavine.duckdetector:duckdetector-sdk:0.0.0-SNAPSHOT")
}
```

The AAR's manifest brings in the SDK's services, the MIME group Native Root's throne-hunt stimulus flips, and the app zygote preload; `soter-core` brings the SOTER keystore permission, library and package query. Native Root also contributes a permission tree for its disabled-by-default timing experiment; the SDK declares no requested permissions; see [Permissions](#permissions).

## Scan

```kotlin
val results: List<DetectorResult> = DuckDetector.scan(context)       // every detector, concurrently
DuckDetector.results(context).collect { result -> show(result) }     // each result as it finishes
val su = DuckDetector.detectors.first { it.id == DetectorId("su") }  // one detector, by its id
val result: DetectorResult = su.run(context)
```

`DuckDetector.detectors` lists every detector in the order `scan` starts them. A `DetectorResult` carries the detector's `id`, its `status` and the structured `report` that the app exports for the same evidence. Each detector moves its own collection off the calling dispatcher.

[Compatibility](#compatibility) describes which of these types stay stable across releases.

Results are diagnostic evidence, not a verdict on the device. Read the status as follows:

| `status.severity` | Meaning |
|---|---|
| `DANGER`, `WARNING` | The detector observed evidence; the report says what it saw |
| `ALL_CLEAR` | The probes observed the device and found none of the evidence they look for. This does not prove the device is unmodified |
| `INFO` with `InfoKind.SUPPORT` | A probe was unsupported or unavailable here, so the absence of findings says nothing |
| `INFO` with `InfoKind.ERROR` | The scan failed; the report says why |

## Compatibility

The SDK follows Kotlin's [backward compatibility guidelines for library authors](https://kotlinlang.org/docs/api-guidelines-backward-compatibility.html), and splits its API into two parts with different guarantees.

The stable contract is the public API of `:sdk:runtime`, `:core:detector`, `:core:report` and `:core:evidence`. Kotlin's ABI tools record it in a dump committed under each module's `api/` directory, and CI fails when the API changes without the dump, so every change to the contract is a reviewed diff. Its value types, such as `DetectorResult`, `DetectorReport` and `PackageVisibility`, are `@ContractValue` classes rather than data classes. They compare, hash and print like data classes but have no `copy` or `componentN`, whose signatures and meaning change as properties are added or reordered. When a property is added, the previous constructor stays as a secondary constructor, so a host compiled against an earlier release still links.

The opt-in API is each detector's own typed object, such as `SuDetector` with its report and card model. It belongs to that detector and is not part of the stable contract. It is marked `@DetectorSpecificApi`, an error-level opt-in, so using it needs `@OptIn(DetectorSpecificApi::class)`, as the sample does, and an acknowledgement that it may change in any release.

Nothing in the stable contract is removed or changed incompatibly in one step. The old declaration is first marked `@Deprecated` with a message that names its replacement and, where one exists, a `ReplaceWith`. In later releases the deprecation level moves from `WARNING` to `ERROR` to `HIDDEN`, and only then is the declaration removed. Adding declarations is compatible and needs no cycle.

## Process hooks

Some evidence can only be captured at particular points of the process lifecycle. The AAR's manifest wires the app zygote preload itself; the launch capture and the mount-view sampler need a step from the host. Without these hooks, every detector still runs, and the evidence that needs them is reported as unavailable or failed, never as clean.

### App zygote preload

The AAR's manifest names `DuckDetectorZygotePreload` in `android:zygotePreloadName`, and the manifest merger gives it to your application; there is nothing to declare. If your application has its own `ZygotePreload`, the merger reports a conflict rather than dropping either. Keep yours and call the SDK's from it:

```xml
<application
    android:zygotePreloadName="com.example.HostZygotePreload"
    tools:replace="android:zygotePreloadName">
```

```kotlin
class HostZygotePreload : ZygotePreload {
    private val duckDetector = DuckDetectorZygotePreload()

    override fun doPreload(appInfo: ApplicationInfo) {
        duckDetector.doPreload(appInfo)
        // the host's own app zygote work
    }
}
```

The preload runs each detector's app zygote work, such as Native Root's throne-hunt watch, and then captures the SELinux context validity evidence, before any isolated process forks from the app zygote. Without it, the SELinux and LSPosed carriers report their app zygote evidence as unavailable, and Native Root's throne-hunt carrier reports its collection as failed.

Each step of the preload is logged at info level under the `DuckZygotePreload` tag. If the app zygote is killed during the preload, it leaves no crash report, and the last line under that tag names the step it had reached.

### Early launch capture

The Mount and Virtualization detectors compare their scan with evidence captured before the first Java activity. Make the SDK's launcher your launch activity and name the activity it hands over to:

```xml
<activity
    android:name="android.app.NativeActivity"
    android:exported="true"
    android:theme="@android:style/Theme.Translucent.NoTitleBar">
    <meta-data android:name="android.app.lib_name" android:value="duckdetector" />
    <meta-data
        android:name="com.eltavine.duckdetector.launch_activity"
        android:value="com.example.HomeActivity" />
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

The launcher captures the evidence, then starts the activity that `com.eltavine.duckdetector.launch_activity` names, a fully qualified class in your package, with the evidence as extras. Without that entry it starts `<applicationId>.MainActivity`, as the app's launcher does. Call `DuckDetector.captureLaunchEvidence(intent)` from that activity's `onCreate` and `onNewIntent`. Without the launcher, the Mount and Virtualization detectors report the early capture as unavailable.

### Mount-view sampler

The isolated mount-view scanner is ported from PrivIsolated, which creates a WebView before it binds any helper process. The app keeps that order. Before its UI starts, it attaches the invisible view from `DuckDetector.createProcMountSampler(activity)` as a 1x1 child, and destroys it with the activity. Do the same to scan under the same conditions as the app.

The sampler's renderer runs as an isolated service of your package, so ActivityManager stops it whenever it stops the package's services, as it does when any of the package's processes fails to start. WebView kills a host whose renderer exits unless the host handles the exit, so the sampler handles it: it removes itself from its parent and destroys itself. Destroying it again with the activity is harmless.

## Permissions

The SDK declares no requested permissions, so the host decides what its process may observe. The app declares these for detection:

| Permission | Used by | Without it |
|---|---|---|
| `QUERY_ALL_PACKAGES` | The package inventory behind Custom ROM, Dangerous Apps, LSPosed, Native Root and Virtualization | Android's package visibility filtering applies, and the inventory records that the permission was not requested |
| `USE_BIOMETRIC`, `USE_FINGERPRINT` | TEE's biometric and SOTER environment checks, which call `BiometricManager.canAuthenticate` | That call requires `USE_BIOMETRIC` |
| `INTERNET`, `ACCESS_NETWORK_STATE` | TEE's online refresh of Google's attestation revocation list | TEE cannot refresh the list online |
| `INTERNET` | ADB Runtime's first-packet probe of an ADB endpoint this device advertises; the connection never leaves the device | The probe reports the endpoint as permission-limited, so the network contradiction is not evaluated |
| `ACCESS_LOCAL_NETWORK` | ADB Runtime's `NsdManager` discovery of this device's ADB services on Android 17 and later. Neither the app nor the SDK requests it; the user grants it in system settings | Discovery reports that the permission is required, so the network contradiction is not evaluated |

`DuckDetector.packageVisibility(context)` reports whether this process sees the full package list, a filtered one or an unreadable one, with the number of visible packages, so a host can tell before it reads the package-based results whether filtering bounds them.

The SDK declares two `<queries>` entries, which the manifest merger adds to the host. TEE's entry for `com.tencent.soter.soterserver` lets the SOTER environment check tell a missing service from one that package visibility filtering hides. Root Managers' `MAIN`/`LAUNCHER` intent is broad: it makes every app with a launcher activity visible to the host, so that a renamed root manager is still listed. A host that does not want that visibility can drop it with `tools:node="remove"` on the same `<intent>`, at the cost of hiding renamed managers from the launcher enumeration. Either way, a host without `QUERY_ALL_PACKAGES` has filtered package visibility, so Root Managers reports an empty result as partially evaluated rather than clean. Root Managers keeps only matched apps and counts, never the identities of the other apps it checked.

The online revocation refresh also needs the user's consent, which the SDK never asks for itself. Every detector lists the choices it needs in `consents`; TEE declares `TeeRevocationNetworkConsent`; Native Root declares `NativeRootSrcuTimingConsent` for an active local experiment. Read the current answer from `decisions(context)`, record the user's with `decide(context, granted)`, and scan again. Until the user allows it, TEE checks revocation against the bundled snapshot and says so in its report.

```kotlin
val consents = DuckDetector.detectors.flatMap { it.consents }   // what the host should ask the user
TeeRevocationNetworkConsent.decide(context, granted = true)      // then scan again
// Only after explaining the active experiment and obtaining an explicit choice:
NativeRootSrcuTimingConsent.decide(context, granted = true)
```

Native Root's timing experiment stays disabled until its consent is granted. It temporarily adds and removes one signature-protected dynamic permission under `${applicationId}.duckdetector.srcu`, using the merged non-exported `:srcu_timing` service. Do not override that service to run in the main process. The supported trigger is limited to API 31–34 and reviewed kernel families; OEM differences can still make it inconclusive. The watchdog bounds host waiting, but older modified kernels have a known lock-inversion risk that it cannot recover. Timing is supporting contention evidence and does not identify KernelSU. Failure and unconfirmed cleanup remain visible in the report. See [the source, lifecycle and validation record](../../feature/nativeroot/SRCU_TIMING.md) before exposing this consent in a host UI. Removing the permission tree from the merged manifest makes the stimulus unavailable.
