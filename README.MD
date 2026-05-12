# DuckDetector

Disclaimer / 免责声明

English: This software is provided "as is", without warranty of any kind, express or implied. It is designed for educational, diagnostic, and security research purposes only. The developers assume no liability for any direct or indirect damage, data loss, or system instability resulting from the use of this application. Relying on heuristic security detection is at your own risk.

中文: 本软件按“原样”提供，不提供任何明示或暗示的保证。本程序仅供教育、诊断和安全研究目的使用。开发者对因使用本应用程序而导致的任何直接或间接损坏、数据丢失或系统不稳定不承担任何责任。依赖启发式安全检测的风险由您自行承担。


LICENSE: Apache License 2.0

> Development rules: see [CODING_STANDARDS.md](./CODING_STANDARDS.md) before making code, workflow,
> or commit changes.

DuckDetector is an Android security inspection app focused on local, device-side
evidence collection for root-related tampering, runtime hooking, mount
manipulation, attestation trust, and virtualized execution environments.

The project combines a Jetpack Compose UI, modular Kotlin feature packages, and
native C++ / assembly probes to surface detector cards with structured findings,
method coverage, and scan-state summaries.

## Highlights

- Modular detector architecture with feature-specific repositories, mappers,
  view models, and card UIs.
- Native startup preload through a transparent `NativeActivity` launcher for
  early mount and virtualization evidence collection.
- Native runtime probes implemented in C++ and arm64 assembly where timing,
  syscall, or mount visibility matters.
- Cross-process and isolated-process consistency checks for stronger runtime
  validation.
- Dashboard aggregation with per-detector status, top findings, loading states,
  and detailed drill-down cards.
- Mostly local, offline inspection. Network access is only used when the user
  allows online TEE revocation checks in Settings.

## Detector Modules

The current app includes the following major detector areas:

| Module             | Focus                                                                                               |
|--------------------|-----------------------------------------------------------------------------------------------------|
| Bootloader         | Bootloader unlock state and related security posture                                                |
| Custom ROM         | ROM fingerprints, platform-file fallbacks, and ROM indicators                                       |
| Dangerous Apps     | Installed app corroboration for known risky packages                                                |
| Kernel Check       | Kernel build and runtime consistency signals                                                        |
| LSPosed            | Java-side and native LSPosed / Xposed runtime evidence                                              |
| Memory             | Runtime hook residue, suspicious mappings, and loader visibility                                    |
| Mount              | Mount tables, mount consistency, startup preload findings, overlay signals, and namespace anomalies |
| Native Root        | Native root-runtime traces, corroborated residue paths, and low-level system anomalies              |
| Play Integrity Fix | Property spoofing and related runtime consistency checks                                            |
| SELinux            | SELinux mode, policy, audit integrity, and context consistency                                      |
| SU                 | Root binary and runtime root-context indicators                                                     |
| System Properties  | Property consistency, native snapshots, and raw property-area residue                               |
| TEE                | Key attestation, certificate chain analysis, revocation checks, StrongBox, and RKP signals          |
| Virtualization     | Emulator / guest / translation / host-app / consistency / honeypot evidence                         |
| Zygisk             | Zygisk state, FD traps, linker residue, and cross-process evidence                                  |

Supporting app areas such as `dashboard`, `settings`, and `deviceinfo` provide
aggregation, user controls, and device context.

## Architecture

The codebase is organized around feature modules under:

`app/src/main/java/com/eltavine/duckdetector/features/<feature>`

Most features follow the same high-level shape:

- `domain`: report and result models
- `data`: repositories, probes, native bridges, service helpers
- `presentation`: mapper and UI-state reducers
- `ui`: card composables and UI models

Shared infrastructure lives under:

- `app/src/main/java/com/eltavine/duckdetector/core`
- `app/src/main/cpp`

### Runtime pipeline

1. A transparent `NativeActivity` launches first and performs startup preload
   collection for time-sensitive evidence.
2. Preload results are passed into `MainActivity` and captured in in-memory
   preload stores.
3. The Compose app shell creates detector view models and collects feature
   reports.
4. Repositories combine Java-side probes, native bridges, and helper-process
   results into normalized report objects.
5. Card mappers convert reports into dashboard-ready UI models.

### Native components

Native probes live under:

- `app/src/main/cpp/preload`
- `app/src/main/cpp/mount`
- `app/src/main/cpp/virtualization`
- `app/src/main/cpp/asm/arm64`

These components are built into a single shared library and are used for mount
inspection, preload capture, virtualization snapshots, graphics renderer checks,
and arm64 trap / honeypot paths.

## Build Requirements

- Android Studio with Android SDK 37.0
- Android Build Tools `37.0.0`
- JDK 17
- Android NDK `30.0.14904198`
- CMake `4.1.2`

Project build configuration is split between `gradle.properties`,
`build-logic/`, and `app/build.gradle.kts` with:

- `minSdk = 29`
- `targetSdk = 37`
- `compileSdk = 37.0`
- `versionCode = 300 + git commit count`
- `versionName = yyyy.MM.dd-short hash` in the `Asia/Singapore` timezone
- `BuildConfig.isAlphaVersion` is generated from the build logic boolean flag

## Build

### Debug

On Windows:

```powershell
./gradlew.bat :app:assembleDebug
```

On macOS / Linux:

```bash
./gradlew :app:assembleDebug
```

### Release

Release signing is optional and controlled through environment variables:

- `ANDROID_KEYSTORE_PATH`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

If all four variables are present, the release build uses the `ciRelease`
signing config.

Example:

```powershell
$env:ANDROID_KEYSTORE_PATH="C:\path\to\keystore.jks"
$env:ANDROID_KEYSTORE_PASSWORD="***"
$env:ANDROID_KEY_ALIAS="release"
$env:ANDROID_KEY_PASSWORD="***"
./gradlew.bat :app:assembleRelease
```

## Output APK Naming

APK artifacts are renamed through a custom Gradle transformation task. Typical
output names follow this pattern:

- `Duck Detector-<version>-Universal.apk`
- `Duck Detector-<version>-<filter>.apk`

## Testing and Verification

Useful verification commands:

```powershell
./gradlew.bat :app:compileDebugKotlin
./gradlew.bat :app:testDebugUnitTest
./gradlew.bat :app:assembleDebug
```

Because several detectors rely on process state, mount state, native ABI, and
device-specific runtime behavior, manual validation on real hardware remains
important even when unit tests pass.

## Privacy and Network Use

- Detector logic is primarily local and device-side.
- The app does not require root access to run.
- Some probes may report reduced coverage or `support` / `unavailable` states
  when Android sandbox rules or OEM restrictions block access.
- Network access is only relevant for TEE certificate revocation checks, and
  only when the user enables online CRL checks in Settings.

## Project Layout

```text
DuckDetector_new/
|- build-logic/
|- app/
|  |- src/main/java/com/eltavine/duckdetector/
|  |  |- core/
|  |  |- features/
|  |  \- ui/
|  \- src/main/cpp/
|- gradle/
|- scripts/
|- build.gradle.kts
\- settings.gradle.kts
```

## Development Notes

- Detector detail rows are intentionally standardized through a shared composable
  so long labels, statuses, and evidence strings wrap consistently across cards.
- Startup preload heuristics are conservative by design and may be tightened
  further if specific device families produce noisy evidence.
- Virtualization detection is intentionally split across preload, Java probes,
  native probes, helper processes, and isolated processes to reduce reliance on
  any single signal source.

## Limitations

- Security detection is heuristic. No single signal should be treated as perfect
  proof in isolation.
- OEM kernels, Android version differences, mount layout changes, and sandbox
  policies can alter probe coverage or produce device-specific edge cases.
- Some low-level checks are ABI-specific. For example, certain trap paths are
  only fully implemented on `arm64-v8a`.

## Status

This repository is an actively evolving detector application. New modules and
heuristics are still being added, and some detector thresholds may continue to
be tuned to reduce false positives on stock devices.
