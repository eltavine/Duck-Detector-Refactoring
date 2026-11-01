# Installer permission-owner observation

Detection-vector credit: [FldBudin](https://github.com/FldBudin) (GitHub), for the
installer duplicate-permission owner-discovery approach.

## Question and evidence

Can an ordinary application obtain the declaring package of the fixed KernelSU permission
`me.weishu.kernelsu.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` through an unsuccessful self-update?
The producer is PackageManager's global permission registry. The observation identifies a permission
owner, not an authenticated KernelSU manager, a user profile, past execution, or root access. Another
application may declare this string. AndroidX uses `${applicationId}` for this permission, so changing
applicationId and rebuilding generally changes the string. A miss cannot exclude a renamed manager. An owner with a permission-compatible signing key or
lineage also produces no duplicate-permission failure, even when this permission exists.

## Supported implementation and rejection boundaries

The active probe is opt-in, limited to API 33–37. Android 13, 14, 15 and 16 release tag `_r1`, and
`android17-release` at `94b4c163b7dfe5ce3607f7bb8456f9573f7de57d`, were inspected.
In `InstallPackageHelper.preparePackage` the permission owner
signature conflict is checked before the permission's group and before package freezing. The canary
contains just that permission, in a deliberately undefined, application-specific group. Without an
owner conflict, the missing group rejects it before freezing on these implementations. No SystemUI
or Settings permission is used as a sentinel.

A second boundary is independent of the permission registry: the canary declares the existing platform shared UID
`android.uid.system` while the installed application must declare none. The framework package must
actually own that shared UID, and the host signer and certificate history must be disjoint from the
platform shared UID’s merged signing history. The framework certificate is a positive control for
visibility of UID-based certificate queries. This covers key rotations in other members of the
shared UID as well as the framework package itself. Platform-signing hosts are unsupported. This also rejects a fresh install
through shared-UID signature enforcement, even if the host disappears during the session.
Updating the shared UID is rejected with
`INSTALL_FAILED_UID_CHANGED` before replacement. The runtime checks the embedded archive's package,
version, current signer, shared UID, target SDK, permission, group and absence of components before
opening a session. It refuses system apps and archived/shared-UID hosts. Future Android versions are
unsupported until re-audited. OEM changes may cause an earlier rejection; unexpected results remain
inconclusive. The fallback UID check can follow freezing on some implementations, so this probe does
not promise zero process side effects on unvalidated OEM builds.

The APK is linked and signed at build time using the application's selected signing configuration.
Signing keys are never shipped or used at runtime. SDK hosts without this application-specific asset
report unavailable; they do not attempt an unsigned or dynamically rewritten install. The
application composition root owns installation permissions; the detector library does not add them
to SDK hosts.

## Installation lifecycle

The existing consent mechanism keeps the probe disabled until enabled. No unknown-sources settings
or installer confirmation screen is opened. `STATUS_PENDING_USER_ACTION` is reported and the session
is abandoned. Source-install policy, update ownership, verifier behavior, silent-install target SDK
requirements and rate limits remain authoritative. A file lock prevents overlapping probes, a local
60-second cooldown avoids the platform's silent-update throttle, and a 30-second timeout bounds
waiting. Cancellation and all terminal results unregister the receiver, cancel the PendingIntent,
request abandonment of the owned session and remove the temporary APK. System-server session
removal is asynchronous; runtime tests wait for removal before asserting cleanup. No other installer sessions are abandoned.
The experiment necessarily stages an APK and changes installer bookkeeping; it is not a read-only
operation. The missing-group rejection also writes the Android security event `146211400` on
researched branches. Unexpected success disables the experiment and is never reported as a detection.

Only the expected public/legacy status and the exact permission-specific message are accepted.
Fallbacks, signature errors, malformed callbacks, other permission conflicts and changed templates
cannot produce a positive result. The callback is package-restricted, mutable for system result
extras, and received by a non-exported receiver with a unique action and checked session ID.

## Directory observations

After an owner is observed, `stat` examines user IDs 0–999. Successful directory results are retained
only when the UID belongs to that user and an ordinary application appId. This is a bounded search,
not exhaustive user enumeration. Every errno is counted, including ENOENT. Zygote app-data isolation
can hide real directories behind tmpfs, independently of underlying DAC modes; failure does not
negate the owner observation. No profile-directory probe is used: installd prepares reference profile
directories during app-data creation, so directory existence does not establish execution history.

## Authoritative references

- [SessionParams.setRequireUserAction](https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams#setRequireUserAction(int))
- [Manifest sharedUserId](https://developer.android.com/guide/topics/manifest/manifest-element#uid)
- [AndroidX core manifest](https://android.googlesource.com/platform/frameworks/support/+/androidx-main/core/core/src/main/AndroidManifest.xml)
- [Android 13 preparePackage](https://android.googlesource.com/platform/frameworks/base/+/android-13.0.0_r1/services/core/java/com/android/server/pm/InstallPackageHelper.java)
- [Android 14 preparePackage](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/services/core/java/com/android/server/pm/InstallPackageHelper.java)
- [Android 15 preparePackage](https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/services/core/java/com/android/server/pm/InstallPackageHelper.java)
- [Android 16 preparePackage](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/InstallPackageHelper.java)
- [Android 17 preparePackage](https://android.googlesource.com/platform/frameworks/base/+/94b4c163b7dfe5ce3607f7bb8456f9573f7de57d/services/core/java/com/android/server/pm/InstallPackageHelper.java)
- [Android 16 UID certificate queries and visibility](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/ComputerEngine.java)
- [Android 16 shared-UID signature enforcement](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageManagerServiceUtils.java)
- [Android 16 session policy and result dispatch](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageInstallerSession.java)
- [Android 16 ProcessList isolation gates](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/services/core/java/com/android/server/am/ProcessList.java)
- [Android 16 Zygote data/profile mounts](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/jni/com_android_internal_os_Zygote.cpp)
- [Android 16 installd profile preparation](https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r1/cmds/installd/InstalldNativeService.cpp)

## Reproducible emulator verification

Build the debug application and instrumentation APK, then run against a disposable emulator:

```sh
./gradlew :feature:rootmanagers:data:testDebugUnitTest \
  :feature:rootmanagers:domain:test :feature:rootmanagers:presentation:test \
  :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug
python3 feature/rootmanagers/research/installer-canary/verify.py \
  --sdk "$ANDROID_HOME" --serial emulator-5580 \
  --apk "app/build/outputs/apk/debug/<debug-apk>.apk" \
  --test-apk app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
```

The script uses a temporary signing key for the unrelated owner fixture and the standard debug key
for the host rejection fixture. It creates and removes one secondary user, resets the fixture package
and source-install app-op, and temporarily allows this installer unlimited silent-update attempts.
The production probe retains its 60-second local cooldown. Every evaluated case checks that host
version, code path, UID and launcher remain intact, and that temporary files and sessions are cleaned.
The post-commit timeout path is exercised with a zero-duration test deadline.

Validated environment: API 36, arm64-v8a, `google/sdk_gphone64_arm64/emu64a:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys`,
kernel `6.6.66-android15-8-gd0c43a640eab-ab13812146-4k`. Disabled, denied-source, absent permission,
retained permission, foreign-user-only owner, rebuilt permission, local cooldown, callback timeout,
cancellation after session creation, independent shared-UID update rejection, and fresh-install signer
rejection cases passed. The foreign-user fixture has no launcher and is not started. These are synthetic permission-owner fixtures, not a claim of testing an actual KernelSU
manager or every repackaging implementation. API 29 was separately exercised: the probe reports
unsupported before opening a session and preserves the host. Android 13–15 and 17 still require
device validation; their source review does not establish OEM-wide compatibility.

- [Applicable ACK 6.6 stat and LSM hooks](https://android.googlesource.com/kernel/common/+/refs/heads/android15-6.6/fs/stat.c)
- [PackageManager status conversion](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/java/android/content/pm/PackageManager.java)

## Verification limits

Unit tests cover result classification and evidence wording. Device verification must cover absent
and present permission owners, a rebuilt permission, source-install denial, timeouts/cancellation,
user isolation, and independent shared-UID rejection with the group guard removed. Emulator results
do not establish compatibility with every OEM or Android release.
