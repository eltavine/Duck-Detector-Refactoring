# Architecture follow-ups

These are the known gaps and pending checks the module refactor left. Each gap was kept because fixing it would change detector semantics, shipped binaries or component identity, which the refactor was not allowed to do; each check needs a device the refactor did not have. Remove an entry in the same change that resolves it.

## Text that data layers still read

`check-text-protocols.py` covers presentation, ui, core, SDK, app and native code, but not data layers, which interpret the platform's text by nature. Some of what they read is DuckDetector's own. The Mount repository filters the early preload capability's findings by splitting their `type|message` strings, although the capability has a typed accessor for the messages. The Native Root cgroup probe compares its own rule labels. The SELinux attr/current results carry their outcome as string constants the capability defines. Each stays inside the unit that wrote or received the text; typing them would let the checker cover data layers too.

## SELinux note statuses

The SELinux card's policy and audit notes are typed, but each kind keeps the status the old keyword search gave its text, including three that look wrong. "No permissive domains detected" is a warning, because its text contains "permissive". "Security classes look complete" is informational, because its text contains none of the searched words. And the note for audit probes that exposed tampering is informational for the same reason, although its state is the strongest audit finding. Correcting them changes what the card shows, so each needs a deliberate decision.

## SELinux context validity merges two failures

The context validity oracle is untrusted either because its controls failed or because its repeated writes disagreed, and the repository reports both as one self-test failure. The card has separate verdicts for the two ("untrusted" and "unstable context oracle"), but its reading sets `repeatabilityFailed` for every self-test failure, as the old text match on "repeatability failed" did. The probe result keeps `oracleControlsPassed` and `ksuResultsStable`, so the reading could tell the causes apart. Doing so changes the card's and the export's verdict for devices whose controls fail, so it needs a deliberate change.

## Release native builds never use the Release configuration

Release variants build the native libraries with CMake's `RelWithDebInfo` configuration because nothing selects `Release`. The `$<CONFIG:Release>` flags in `sdk/runtime/src/main/cpp/CMakeLists.txt` therefore never reach shipped builds. These flags are `-ffunction-sections`, `-fdata-sections`, hidden visibility, `INTERPROCEDURAL_OPTIMIZATION_RELEASE` and `-Wl,--gc-sections`. The shipped `libduckdetector.so` is compiled with `-O2 -g` and default visibility; only `libmain.so` always hides its symbols. The refactor kept this behavior and verified it unchanged. Enabling the flags changes shipped binaries and the code layout of timing-sensitive probes, so it needs on-device validation of the timing and trap probes before it lands.

## The prop area hole scan assumes a dirty backup area on Android 10

From Android 11, bionic reserves a `PROP_VALUE_MAX` dirty backup block right after each property area's root node; Android 10's `prop_area.h` starts allocating right there. The two probes that walk property areas now share the systemproperties unit's parser. The custom ROM property integrity probe marks that block as occupied only from API 30, but the system properties hole scan marks it on every release. On Android 10 the scan therefore never reports a hole in those 92 bytes, and it skips areas too small to hold the block. The refactor kept this behavior. Passing the API level changes the scan's findings on Android 10 devices, so it needs validation on one.

## Lint translation completeness is module-scoped

Lint's `MissingTranslation` check compares a string only against the locales present in the module that declares it. `mount_diagnostic_clipboard_label` and `native_root_diagnostic_clipboard_label` moved from `:app` into feature modules. Those modules have fewer locale folders, so their missing translations are no longer reported, although the strings themselves are unchanged. `feature/tee/ui` has every locale since it took over TEE's consent strings, so lint reports `tee_diagnostic_clipboard_label`'s missing translations again. Add the missing translations, or add a repository-wide translation completeness check that does not depend on module layout.

## Forked probe children outside the disposable child runner

`run_disposable_child` in `:core:native` stops a child at a deadline, stops waiting for it after a second one, and lets a fault end it without a tombstone. Only the SELinux status page probe uses it so far. Seven older children fork and reap on their own and block in `waitpid` until the child exits: Native Root's KernelSU supercall, SUSFS, KernelPatch superkey and KernelPatch supercall latency probes, Mount's statx support check, the helper process's sacrificial syscall pack and the early preload's mntent buffer lookup. Moving one onto the runner changes how a hung or faulting child is reported, so each needs its own change and on-device validation, and the latency probe must keep its measured path in one translation unit.

## Shared per-scan platform snapshots

Each detector still collects its own platform evidence during its scan, even when several detectors read the same source, such as the package inventory or system properties. A scan session that captures such evidence once and hands the same snapshot to every consumer would make cross-detector correlation exact, but it changes probe timing and ordering, so it needs its own design and on-device validation.

## Public API dumps bypass KGP's abiValidation

The Kotlin Gradle plugin's `abiValidation` fails on Android libraries built with AGP's built-in Kotlin: in KGP 2.4.20, the input that supplies their class files has no value. `DuckDetectorPublicApiPlugin` therefore hands AGP's release classes to `org.jetbrains.kotlin:abi-tools`, the engine `abiValidation` runs, and writes the same dump format. When `abiValidation` supports these libraries, replace the plugin with `kotlin { abiValidation() }` in the four contract modules; the committed dumps should not change.

## TEE probes that classify keystore errors by message

Two TEE deep checks still read platform error text. The oversized challenge probe counts any exception as a rejection, so a busy or failing keystore reads as the expected answer. The update subcomponent probe recognises a key-not-found style failure by matching "KEY_NOT_FOUND" or "error 7" in the exception message. On Android 13 and later, `android.security.KeyStoreException.getNumericErrorCode()` gives the typed code. Classify by it where it exists, and report the probe as not completed otherwise.

## The storage path filter check lives in Kernel Check

`KernelCvePatchProbe` tests whether `/sdcard/Android/data` can be listed through paths with ignorable Unicode codepoints, which is MediaProvider's path handling rather than a kernel property, and the report calls it CVE-2024-43093 without a reviewed fix reference. Move it next to the Dangerous Apps directory listing methods that use the same bypass, or into a storage detector, and cite the fix. The move changes a card and the export, so it needs its own change with a golden update.

## Discovery-only evidence

Eleven evidence record entries start with "Discovery only:" because they rest on a tool's observed behaviour or on a source this review did not read. They are the KernelSU interfaces, the kernel token catalogs, TrickyStore's in-process signatures, the TEE timing skip signatures, SOTER, LSPosed's class and log names, Zygisk's residue patterns, the Memory prologue and handler heuristics, and the vendor-specific bootloader and Widevine behaviour. Review each tool's source, or the vendor documentation, and replace the marker with the reference, or lower the signal's confidence where the source does not support it.

## "Clean" rows that mean "not observed"

Most method rows say "Clean" when a probe ran and saw nothing, and several say "Normal". AGENTS.md section 19 prefers "not observed", which does not suggest the device was proven clean. Changing the word changes every card and the golden export, so it needs one cross-detector copy change rather than piecemeal edits.

## SOTER environment check swallows inspector failures

`SoterCapabilityProbe` wraps the environment inspector in `runCatching` and falls back to an empty snapshot. `BiometricManager.canAuthenticate` needs `USE_BIOMETRIC`, so a host without it gets an "abnormal environment" result of false instead of "not evaluated". Carry the inspector's failure into `TeeSoterState` and show the environment check as unavailable.

## Device validation of the manifest hooks

Two process hooks changed so that SDK hosts need fewer manifest steps. They were checked against AOSP sources, native builds and the merged manifests, not on a device:

- Native Root declares the throne-hunt MIME group on its carrier service instead of the app's `MainActivity`. From Android 11 through main, a package declares the MIME groups of every component's intent filters, and `setMimeGroup` updates services like activities before it rewrites packages.list. Check that `dumpsys package` lists the group and that the stimulus applies.
- The launcher reads the activity it starts from its own `<meta-data>` through `PackageManager.getActivityInfo`, as `NativeActivity` reads `android.app.lib_name`. Check that the app, which names none, still starts `MainActivity`, and that the sample starts `ScanActivity` with the evidence.

## Device validation of the evidence review

The evidence review changed what several probes report. These changes were verified with JVM tests and native builds for all four ABIs, not on devices:

- the netlink boundary's applicability by release and target SDK;
- the SUSFS outcome codes;
- the paths now reported as not observable in Native Root, SU and SELinux;
- the TEE deep checks that now read "Did not complete";
- the gate on app attestation keys;
- the operation error path grading;
- the KernelPatch latency availability.

Validate them on a stock device, a rooted device with /data/adb present, an SDK host with an old target SDK, and a non-arm64 device before relying on the new states in a release.

## SID-table consistency device validation

The SID-table experiment is implemented with pinned ACK/AOSP/KernelSU source references,
JVM regressions and host-native injected IO/runner tests. No Android device was attached.
Before relying on this warning in a release, compare the same device/kernel configuration
with stock SELinux, pre-a810677 KernelSU hiding enabled/disabled, and the synchronization fix.
Also exercise permission-limited/vendor kernels, existing candidates, background process
activity, policy reloads, repeated carrier starts and non-arm64 devices. Verify preload
latency, bounded SID-table/AVC effects and child cleanup. Record how often a normal scan ends
inconclusive: processes that start while the app zygote preloads, including the scan's own helper
and isolated processes, can register new labels and break the quiet bookends. Global statistics cannot exclude
hidden reloads or attribute inserts to one process, so even a repeatable pattern remains
supporting evidence and must not be promoted to tool identification or a danger finding.

## Root manager catalogues across detectors

Three detectors name root manager packages from separate lists: Root Managers' catalogue, Native
Root's `KERNELSU_MANAGER_PACKAGES`, and Dangerous Apps' root-tool entries. Root Managers is the only one
that identifies a manager past a rename, by the manager key each KernelSU-family kernel trusts and by
the daemons the managers ship, and it already reads package visibility through
`capability/packageinventory`. The package lists still overlap. They should not be presented as
independent evidence, because Root Managers' launcher and certificate reads and Native Root's manifest
read all pass through PackageManager and `AppsFilter`; only Dangerous Apps' file-system methods take
another path. Moving the manager-key catalogue and the signing-certificate read into a capability
would let Native Root and Dangerous Apps match renamed managers too. It needs one per-scan read of the
inventory (see "Shared per-scan platform snapshots") and on-device validation before it lands.

The manager key is read only in the caller's profile, because PackageManager answers for the calling
user. Reading the v2 signature block from `ApplicationInfo.sourceDir` would extend the key to apps
installed only in another profile; that needs an APK signing-block parser and a device pass on the
SELinux access to other profiles' APKs.

## Optional SRCU timing calibration

Native Root's disabled-by-default timing experiment is implemented with typed failures, controls and a private same-UID carrier. Its source chain and remaining device matrix are in [SRCU_TIMING.md](../../feature/nativeroot/SRCU_TIMING.md). No device result establishes its thresholds yet. Verify each vendor's synchronous permission persistence and fsnotify teardown, measure stock and fixed-KernelSU noise, and exercise cancellation/process-death cleanup before relying on a warning or changing the default. Latest KernelSU moves the normal scan outside SRCU and removes manager-absent full scans, so lack of delay cannot exclude it. A watchdog cannot recover the old kernel/system_server lock inversion.
