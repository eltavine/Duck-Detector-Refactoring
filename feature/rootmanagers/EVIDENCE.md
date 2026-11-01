# Root Managers evidence record

Status: reviewed

Root Managers asks whether any mainstream root manager app (the KernelSU family, APatch, Magisk or
SKRoot) is installed and observable from this app, in the caller's own profile or in any other
profile the LauncherApps API exposes. A match is a finding that such an app is installed — not a
claim that the device is rooted, that the manager is active, or that no other manager exists. A
clean result needs every returned profile searched, full package visibility, the caller seen in its
own launcher list and readable signing certificates; anything less is reported as partially
evaluated, never as clean. This detector reads public `PackageManager`, `LauncherApps`,
`LauncherActivityInfo` and `ApplicationInfo` values, the hidden `ApplicationInfo.zygotePreloadName`
field and whether catalogued file names exist in each app's native library directory; it reads no
APK contents, no root state and no app data, and it keeps no unmatched app's identity.

## Version model

| Platform | AOSP lifecycle difference | Duck policy |
| --- | --- | --- |
| Android 10 / API 29 | Package visibility filtering does not exist yet; every installed app is visible. `LauncherAppsService` already injects the synthetic app-details entry for an app that hid its icon. `ApplicationInfo.zygotePreloadName` exists. | `minSdk 29`. Visibility is full by construction, so the shared visibility policy reports it as such. |
| Android 11–14 / API 30–34 | `AppsFilter` filters queries for callers targeting API 30+, unless the caller requests `QUERY_ALL_PACKAGES` or a `<queries>` element grants the package. | The app requests `QUERY_ALL_PACKAGES`; an SDK host that removes this module's `<queries>` entry and lacks it is reported as filtered, so its empty results are partial. |
| Android 15+ / API 35+ | Private Space is a hidden profile: `LauncherAppsService.getUserProfiles()` leaves it out unless the caller holds `ACCESS_HIDDEN_PROFILES_FULL`, or is the home role holder with `ACCESS_HIDDEN_PROFILES`. | A manager installed only in Private Space is not observable; the record says so instead of claiming absence. |
| All releases | `getActivityList` returns `Collections.EMPTY_LIST` both for a profile with nothing to launch and for one `canAccessProfile` refuses (disabled, being removed, hidden); only an unrelated profile throws `SecurityException`. `PackageManager` answers for the calling user only. | An empty profile is "not observed", never searched. Certificates and the caller-profile sweep cover the caller's profile; other profiles are searched through their launcher lists. |

AOSP baseline read for this detector: `frameworks/base` main as of 2026-10-08 —
`services/core/java/com/android/server/pm/LauncherAppsService.java` (`getUserProfiles`,
`canAccessProfile`, `getLauncherActivities`, `shouldShowSyntheticActivity`),
`core/java/android/content/pm/LauncherApps.java` (`getActivityList`, `convertToActivityList`),
`services/core/java/com/android/server/pm/UserManagerService.java` (`isProfileAccessible`),
`core/java/android/content/pm/ApplicationInfo.java` (`zygotePreloadName`, `writeToParcel`),
`core/java/android/content/pm/PackageManager.java` (`APP_DETAILS_ACTIVITY_CLASS_NAME`) and
`core/java/android/os/UserHandle.java` (`hashCode`).

## Measured family anchors

Manager keys are the defaults each family's own kernel compiles in; the other anchors are read from
each manager's manifest, build files and sources at the listed revision.

| Family | Packages | Manager key (bytes, SHA-256 prefix) | Code namespace / class names | Native payloads | Source revision |
| --- | --- | --- | --- | --- | --- |
| KernelSU | `me.weishu.kernelsu` (`.pr` builds; MKSU's default too), `io.github.a13e300.mksu` (older MKSU, kept in step with Native Root's list, not in current source) | 827 (`0x033b`), `c371061b…`; 885 (`0x375`), `484fcba6…` (KOWX712 fork) | `me.weishu.kernelsu`, `.KernelSUApplication`, `.magica.AppZygotePreload` | `libksud.so` | tiann/KernelSU `24d9bc37`; 5ec1cff/KernelSU `6a4cac03` |
| KernelSU-Next | `com.rifsxd.ksunext` | 998 (`0x3e6`), `79e59011…` | `com.rifsxd.ksunext`, `.KernelSUApplication` | `libksud.so` | KernelSU-Next/KernelSU-Next `3daa5787` |
| SukiSU Ultra | `com.sukisu.ultra` (`.pr` builds) | 860 (`0x35c`), `947ae944…` | `com.sukisu.ultra`, `.KernelSUApplication`, `.magica.AppZygotePreload` | `libksud.so` | SukiSU-Ultra/SukiSU-Ultra `42d7fda3` |
| ReSukiSU (BakaSU) | `com.resukisu.resukisu` | 887 (`0x377`), `d3469712…` | `org.bakasu.bakasu`, `.KernelSUApplication`, `.magica.AppZygotePreload` | `libksud.so` | Baka-SU/BakaSU `373303c5` |
| APatch | `me.bmax.apatch` | none: KernelPatch authorises the superkey | `me.bmax.apatch`, `.magica.AppZygotePreload`; `.APApplication` corroborates only | `libapd.so`, `libkptools.so`, `libkpatch.so` | bmax121/APatch `52600361` |
| SKRoot | `com.linux.permissionmanager` | none published | `com.linux.permissionmanager` (Pro: `…helper.AppZygotePreload`); label `SKRoot(…)` | none catalogued | abcz316/SKRoot-linuxKernelRoot `7ad782c8` |
| Magisk | `com.topjohnwu.magisk`, `io.github.vvb2060.magisk` | none: a repackaged app is re-signed with a fresh key | `com.topjohnwu.magisk` | `libmagisk.so`, `libmagiskinit.so` | topjohnwu/Magisk `cefa2730` |

Notes:
- SukiSU and BakaSU build their manager under any `KSU_PACKAGE_NAME`/`KSU_NAME`, and KernelSU-Next's
  `manager/spoof` script randomises `com.rifsxd.ksunext` throughout the sources. None of these change
  the signing key, which their kernel requires, or the `.KernelSUApplication` simple name and `libksud.so`.
- `libbusybox.so` and `libmagiskpolicy.so` are left out of the payloads: APatch ships and runs both.
  `libmagiskboot.so` is left out because other boot tools bundle it.
- ReSukiSU continues upstream as BakaSU, which keeps the `com.resukisu.resukisu` applicationId but
  moved its code namespace to `org.bakasu.bakasu`. SukiSU now declares a `com.sukisu.ultra.magica`
  zygote preload, and SKRoot labels itself `SKRoot(Lite)`/`SKRoot(Pro)`, not `PermissionManager`.

## Signals

### Launcher visibility enumeration

- Observable signal: the launcher activities `LauncherApps.getActivityList(null, user)` returns for every profile in `getProfiles()`, with the `ApplicationInfo` each `LauncherActivityInfo` carries.
- Producing subsystem: the system `LauncherAppsService`, gated by `canAccessProfile`, and the package visibility model enforced by `AppsFilter` in PackageManager.
- Mechanism: `getUserProfiles()` returns the caller's profile group minus hidden profiles; `getLauncherActivities` queries MAIN/LAUNCHER activities for the target user with the caller's uid, so visibility filtering applies; a refused profile returns null, which the client turns into an empty list.
- References: frameworks/base services/core/java/com/android/server/pm/LauncherAppsService.java; core/java/android/content/pm/LauncherApps.java; services/core/java/com/android/server/pm/UserManagerService.java; developer.android.com package visibility documentation.
- Applicability: `minSdk 29`; filtering applies from Android 11 to callers targeting API 30+; hidden profiles are excluded from Android 15.
- Visibility limits: Private Space, secondary users, a disabled or removed profile and any profile seen from inside a managed profile are not observable; an empty profile is recorded as not observed, a `SecurityException` as denied, and the caller's absence from its own list marks the evaluation partial.
- Result states: evaluated (profiles searched), unavailable (no service, refused, or no profile returned an activity), undecidable (no profile returned); per profile searched, not observed or denied.
- Interpretation: a record is evidence an app is installed in that profile; only a fully searched, fully visible evaluation lets an empty result read as clean.

### Manager signing key

- Observable signal: the length and SHA-256 of each certificate `PackageManager.getInstalledPackages(GET_SIGNING_CERTIFICATES)` reports for an app in the caller's profile.
- Producing subsystem: PackageManager's verified signing details, and the manager check each KernelSU-family kernel compiles in.
- Mechanism: `Signature.toByteArray()` is the DER certificate of the signer, the first certificate of the first signer in the APK signature block; `kernel/manager/apk_sign.c` hashes exactly that certificate and accepts the manager only when its length and SHA-256 equal the build's `EXPECTED_SIZE`/`EXPECTED_HASH`, so a matching app is signed by the key that kernel trusts, whatever its package, label or classes are now.
- References: source.android.com APK Signature Scheme v2; frameworks/base core/java/android/content/pm/SigningInfo.java and Signature.java; tiann/KernelSU kernel/manager/apk_sign.c and kernel/Kbuild; KernelSU-Next, SukiSU-Ultra kernel/Kbuild; Baka-SU/BakaSU kernel/manager/manager_sign.h.
- Applicability: API 28+ `SigningInfo`; caller's profile only, because PackageManager answers for the calling user; the rotation history is included so a rotated key still shows the original.
- Visibility limits: a builder may compile another key into the kernel, and SukiSU/BakaSU accept a dynamically registered key, so a self-signed manager escapes this anchor; APatch and Magisk publish no manager key; an app whose signing details cannot be read is counted as a failed read, and no readable certificate at all marks the evaluation partial.
- Result states: matched (family key), not matched, unreadable (no signing details).
- Interpretation: a match identifies the family with high confidence on its own; it is still evidence of an installed app, not of an active root.

### Native payloads

- Observable signal: the existence of a catalogued daemon (`libksud.so`, `libapd.so`, `libkptools.so`, `libkpatch.so`, `libmagisk.so`, `libmagiskinit.so`) in an app's `ApplicationInfo.nativeLibraryDir`.
- Producing subsystem: the package installer, which extracts native libraries for an app built with legacy packaging, and the manager, which executes them from that directory.
- Mechanism: the managers package their daemons as `lib*.so` with `useLegacyPackaging` and run them from `nativeLibraryDir` (KernelSU `KsuCli.kt` and `AppZygotePreload.java`, APatch `APatchCli.kt`, Magisk `MagiskInstaller.kt`); `Os.stat` on the path needs only search permission, `ENOENT` is an absence and any other errno an unread directory.
- References: developer.android.com android.system.Os; frameworks/base core/java/android/content/pm/ApplicationInfo.java (nativeLibraryDir); tiann/KernelSU manager/app/build.gradle.kts and KsuCli.kt; bmax121/APatch app/build.gradle.kts; topjohnwu/Magisk app/build-logic Setup.kt.
- Applicability: every observed app in every searched profile, since installs in all profiles share `/data/app`; one stat per catalogued name, once per directory.
- Visibility limits: an app built without legacy packaging keeps its libraries inside the APK and leaves no file; a name another lineage also ships is excluded, so a payload never points at the wrong lineage; an unreadable directory is counted, not treated as clean.
- Result states: present, absent, unread.
- Interpretation: a payload alone identifies the lineage at medium confidence; with any other anchor the match is high confidence.

### Hidden launcher icon

- Observable signal: a launcher entry whose component is `android.app.AppDetailsActivity`.
- Producing subsystem: `LauncherAppsService.getLauncherActivities`, which injects a synthetic app-details entry for an app that hid its icon.
- Mechanism: when `Settings.Global.SHOW_HIDDEN_LAUNCHER_ICON_APPS_ENABLED` is not 0, the target is not a managed profile and the device has no device owner, `shouldShowSyntheticActivity` adds the entry for a non-system app that requests permissions and declares a launcher activity enabled by default but now disabled.
- References: frameworks/base services/core/java/com/android/server/pm/LauncherAppsService.java; core/java/android/content/pm/PackageManager.java (APP_DETAILS_ACTIVITY_CLASS_NAME); core/java/android/app/AppDetailsActivity.java.
- Applicability: Android 10 and later, in unmanaged profiles of devices without a device owner.
- Visibility limits: the setting can be turned off, and managed profiles and device-owner devices never inject the entry; an app that declares no launcher activity at all is reachable only through the caller-profile sweep and never reads as hidden.
- Result states: hidden icon, launcher icon present, not applicable.
- Interpretation: an identified manager with a hidden icon is presence plus concealment and is rated danger, as Dangerous Apps rates an app hidden from PackageManager; a weak-only match with a hidden icon stays informational.

### Manifest identity anchors

- Observable signal: `ApplicationInfo.packageName`, `ApplicationInfo.className`, `ApplicationInfo.zygotePreloadName`, the launcher label and the launcher component class.
- Producing subsystem: the package's own manifest as resolved and parceled by PackageManager.
- Mechanism: `ApplicationInfo.writeToParcel` writes `className` and `zygotePreloadName` unconditionally; manifest class names keep the code namespace when only `applicationId` changes, so a class under a family namespace matches strongly, and a family's simple name (`.KernelSUApplication`, `.magica.AppZygotePreload`) survives a namespace rewrite; `zygotePreloadName` is `@hide` and is read with `HiddenApiBypass.getInstanceFields`, which adds no process-wide exemption.
- References: frameworks/base core/java/android/content/pm/ApplicationInfo.java; core/java/android/content/pm/LauncherActivityInfo.java; each family's manager/app/src/main/AndroidManifest.xml at the revisions under Measured family anchors.
- Applicability: every observed app; `zygotePreloadName` exists from API 29, and an unresolved field drops only the zygote anchor and is reported.
- Visibility limits: a repackaged Magisk randomises package, label and class names; SKRoot declares no application class; labels, a conventional `.MainActivity` and APatch's bare `.APApplication` are words an unrelated app could carry, so they only corroborate.
- Result states: high (a key match, or a strong anchor plus any other), medium (one strong anchor alone), low (two weak anchors only), no match.
- Interpretation: a strong match is a warning; a weak-only match is informational, because two family-shaped words can meet on an unrelated app.

## Relationship to other detectors

Native Root reads the KernelSU manager manifest of its own package list, and Dangerous Apps keeps its
own root-tool entries; Dangerous Apps also lists the official KernelSU and APatch package names. A
manager reported by more than one detector is not independent evidence when both read PackageManager:
`LauncherApps`, `getPackageInfo` and `getInstalledPackages` all pass through PackageManager and
`AppsFilter` in system_server, so a filter there hides from all of them at once. Dangerous Apps'
file-system methods are the independent path.


### Optional installer permission-owner observation

Detection-vector credit: [FldBudin](https://github.com/FldBudin) (GitHub), for the
installer duplicate-permission owner-discovery approach.

- Observable signal: an installer failure names the owner of the fixed candidate KernelSU permission.
- Producing subsystem: PackageManager global permission registry and InstallPackageHelper.
- Mechanism: a signed self-update canary reaches the permission conflict check, with a missing
  permission group as early rejection and a changed shared UID as an independent replacement guard.
- References and version applicability: [implementation and rejection model](../../docs/research/installer-permission-canary.md); API 33–37 only.
- Visibility limits: permission names change on rebuild; owners can be unrelated apps; installation
  authorization, verifier and update ownership can prevent evaluation. Directory mounts can conceal
  cross-user data even after owner discovery. No profile or execution history is inferred.
- Result states: disabled, unsupported, unavailable, user action required, throttled, timed out,
  inconclusive, unexpected success, permission owner observed, permission conflict not observed.
- Interpretation: informational permission-name evidence, independent of launcher enumeration.
  Successful directory stats add bounded user/UID coordinates; every errno remains a visibility
  limitation. Failure never negates owner evidence or establishes manager absence.
