# DuckDetector

<img src="https://github.com/947409161/Duck-Detector-Refactoring/blob/master/DuckDetector.jpg" align="right" width="120" />


![Android][badge-android]
![targetSdk][badge-target-sdk]
![Kotlin][badge-kotlin]
![Jetpack Compose][badge-compose]
![NDK][badge-ndk]

DuckDetector is an Android security inspection app focused on local, device-side
evidence collection for root-related tampering, runtime hooking, mount
manipulation, attestation trust, and virtualized execution environments.

The app combines a Jetpack Compose UI, modular Kotlin detector packages, and
native C++ / assembly probes to surface detector cards with structured findings,
method coverage, and scan-state summaries.

> Development rules: read [CODING_STANDARDS.md](./CODING_STANDARDS.md) before
> changing code, workflows, or commit history.

## Highlights

- Modular detector architecture with feature-specific repositories, mappers,
  view models, and card UIs.
- Native startup preload through a transparent `NativeActivity` launcher for
  early mount and virtualization evidence collection.
- Native C++ and assembly probes for timing-sensitive, syscall-level, mount, and
  runtime visibility checks.
- Cross-process and isolated-process validation to reduce reliance on any
  single signal.
- Mostly local inspection. TEE revocation checks use a built-in snapshot by
  default; network access is only used when optional online refresh is enabled
  in Settings.

## Detector Coverage

Current detector areas include:

`Bootloader`, `Custom ROM`, `Dangerous Apps`, `Kernel Check`, `LSPosed`,
`Memory`, `Mount`, `Native Root`, `Play Integrity Fix`, `SELinux`, `SU`,
`System Properties`, `TEE`, `Virtualization`, and `Zygisk`.

Supporting areas such as `dashboard`, `settings`, and `deviceinfo` provide
aggregation, user controls, and device context.

## Compatibility

| Target | Notes |
|--------|-------|
| Android | Android 10+ (`minSdk 29`), built against `targetSdk 37` / `compileSdk 37.0`. |
| ABI | Native probes are available through the NDK layer; several low-level trap paths are primarily `arm64-v8a`. |
| Device state | Runs without root and is intended for both stock and modified environments. |
| Coverage | Some checks may degrade to `support`, `unavailable`, or reduced-coverage states when OEM or sandbox rules block access. |
| Network | Local by default; built-in TEE revocation checks always run, and online access is only used for optional revocation feed refresh. |

## User Interface

- Compose dashboard with detector cards, scan-state summaries, top findings,
  and detail rows.
- Shared card patterns keep long labels, statuses, and evidence strings
  readable across modules.
- Settings and device-info screens keep optional checks and device context
  separate from detector results.

## Architecture Snapshot

```text
Duck-Detector-Refactoring/
|- app/
|  |- src/main/java/com/eltavine/duckdetector/
|  |  |- core/
|  |  |- features/
|  |  \- ui/
|  \- src/main/cpp/
|- build-logic/
|- gradle/
|- scripts/
|- build.gradle.kts
\- settings.gradle.kts
```

Most detector features follow the same package shape:

- `domain`: report and result models
- `data`: repositories, probes, native bridges, and service helpers
- `presentation`: mappers and UI-state reducers
- `ui`: detector cards and UI models

Native probes live under `app/src/main/cpp` and are built into a shared library
used for preload capture, mount inspection, virtualization snapshots, renderer
checks, and low-level trap paths.

## Build

Requirements:

- Android Studio with Android SDK `37.0`
- Android Build Tools `37.0.0`
- JDK `17`
- Android NDK `30.0.14904198`
- CMake `4.1.2`

Debug build:

```powershell
./gradlew.bat :app:assembleDebug
```

Useful verification:

```powershell
./gradlew.bat :app:compileDebugKotlin
./gradlew.bat :app:testDebugUnitTest
./gradlew.bat :app:assembleDebug
```

Release signing is controlled by `ANDROID_KEYSTORE_PATH`,
`ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, and `ANDROID_KEY_PASSWORD`.
When all four are present, the release build uses the `ciRelease` signing config.

## Privacy And Limits

- Detector logic is primarily local and device-side.
- The app does not require root access to run.
- Some probes may report reduced coverage or `support` / `unavailable` states
  when Android sandbox rules or OEM restrictions block access.
- Security detection is heuristic. No single signal should be treated as perfect
  proof in isolation.
- Some low-level checks are ABI-specific; several trap paths are primarily
  implemented for `arm64-v8a`.

## Status

DuckDetector is actively evolving. New modules and heuristics are still being
added, and detector thresholds may continue to be tuned to reduce false
positives on stock devices.

## Star History

[![Star History Chart][star-history-chart]][star-history]

## Disclaimer

This software is provided "as is", without warranty of any kind. It is designed
for educational, diagnostic, and security research purposes only. The developers
assume no liability for direct or indirect damage, data loss, or system
instability resulting from use of this application. Relying on heuristic
security detection is at your own risk.

本软件按“原样”提供，不提供任何明示或暗示的保证。本程序仅供教育、诊断和安全研究目的使用。
开发者对因使用本应用程序而导致的任何直接或间接损坏、数据丢失或系统不稳定不承担责任。
依赖启发式安全检测的风险由您自行承担。

## License

DuckDetector is licensed under the [Apache License 2.0](./LICENSE).

## Contributors

<div align="center">
  <a href="https://github.com/eltavine"><img src="https://avatars.githubusercontent.com/u/248451253?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/XiaoTong6666"><img src="https://avatars.githubusercontent.com/u/110387028?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/FldBudin"><img src="https://avatars.githubusercontent.com/u/103419694?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/AlexLiuDev233"><img src="https://avatars.githubusercontent.com/u/102930921?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/Searchur"><img src="https://avatars.githubusercontent.com/u/120842622?v=4" width="64" height="64" alt=""></a>
  <br>
  <a href="https://github.com/VictorModi"><img src="https://avatars.githubusercontent.com/u/159055762?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/HSSkyBoy"><img src="https://avatars.githubusercontent.com/u/122550437?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/LingQingBigKing"><img src="https://avatars.githubusercontent.com/u/242912803?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/SQMY-dor"><img src="https://avatars.githubusercontent.com/u/75457662?v=4" width="64" height="64" alt=""></a>
  <br>
  <a href="https://github.com/ZG089"><img src="https://avatars.githubusercontent.com/u/159061718?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/coolzyd9107"><img src="https://avatars.githubusercontent.com/u/35447134?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/wxxsfxyzm"><img src="https://avatars.githubusercontent.com/u/65166044?v=4" width="64" height="64" alt=""></a>
  <br>
  <a href="https://github.com/947409161"><img src="https://avatars.githubusercontent.com/u/127842603?v=4" width="64" height="64" alt=""></a>&nbsp;&nbsp;
  <a href="https://github.com/MiRinChan"><img src="https://avatars.githubusercontent.com/u/148533509?v=4" width="64" height="64" alt=""></a>
</div>

[badge-android]: https://img.shields.io/badge/Android-minSdk%2029-3DDC84?logo=android&logoColor=white&style=flat-square
[badge-build]: https://github.com/eltavine/Duck-Detector-Refactoring/actions/workflows/build.yml/badge.svg?branch=master
[badge-compose]: https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285F4?logo=jetpackcompose&logoColor=white&style=flat-square
[badge-downloads]: https://img.shields.io/github/downloads/eltavine/Duck-Detector-Refactoring/total?style=flat-square
[badge-forks]: https://img.shields.io/github/forks/eltavine/Duck-Detector-Refactoring?style=flat-square
[badge-issues]: https://img.shields.io/github/issues/eltavine/Duck-Detector-Refactoring?style=flat-square
[badge-kotlin]: https://img.shields.io/badge/Kotlin-2.3.21-7F52FF?logo=kotlin&logoColor=white&style=flat-square
[badge-last-commit]: https://img.shields.io/github/last-commit/eltavine/Duck-Detector-Refactoring?style=flat-square
[badge-latest-release]: https://img.shields.io/github/v/release/eltavine/Duck-Detector-Refactoring?include_prereleases&style=flat-square
[badge-license]: https://img.shields.io/github/license/eltavine/Duck-Detector-Refactoring?style=flat-square
[badge-ndk]: https://img.shields.io/badge/NDK-30.0.14904198-555555?style=flat-square
[badge-pulls]: https://img.shields.io/github/issues-pr/eltavine/Duck-Detector-Refactoring?style=flat-square
[badge-release]: https://github.com/eltavine/Duck-Detector-Refactoring/actions/workflows/release-latest.yml/badge.svg
[badge-stars]: https://img.shields.io/github/stars/eltavine/Duck-Detector-Refactoring?style=flat-square
[badge-target-sdk]: https://img.shields.io/badge/targetSdk-37-3DDC84?logo=android&logoColor=white&style=flat-square
[commits]: https://github.com/eltavine/Duck-Detector-Refactoring/commits/master
[forks]: https://github.com/eltavine/Duck-Detector-Refactoring/network/members
[issues]: https://github.com/eltavine/Duck-Detector-Refactoring/issues
[license]: ./LICENSE
[pulls]: https://github.com/eltavine/Duck-Detector-Refactoring/pulls
[releases]: https://github.com/eltavine/Duck-Detector-Refactoring/releases
[star-history]: https://www.star-history.com/#eltavine/Duck-Detector-Refactoring&Date
[star-history-chart]: https://api.star-history.com/svg?repos=eltavine/Duck-Detector-Refactoring&type=Date
[stargazers]: https://github.com/eltavine/Duck-Detector-Refactoring/stargazers
[workflow-build]: https://github.com/eltavine/Duck-Detector-Refactoring/actions/workflows/build.yml
[workflow-release]: https://github.com/eltavine/Duck-Detector-Refactoring/actions/workflows/release-latest.yml
