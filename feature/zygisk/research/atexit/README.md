# Exit-handler AVD comparison

## Reproduction boundary

Use an ARM64 Android 16 AVD with a clean control and separate disposable Magisk module state. Collection itself runs inside the installed host as an ordinary app, and the instrumentation asserts an app UID >=10000 and an `untrusted_app` SELinux domain. Root/adbd administration is used only to prepare module environments and inspect their running state; the collector does not invoke su, enumerate root-only module directories or read another process. Keep SELinux enforcing.

Build `:app:assembleDebug` and `:app:assembleDebugAndroidTest`, install the APKs named by each output-metadata.json, and preverify both packages with `cmd package compile -m verify -f` if the first instrumentation launch spends its startup deadline in ART DEX verification. To test a non-debuggable target while keeping the instrumentation variant and certificate, pass `--init-script /absolute/path/nondebuggable.gradle` with this temporary build configuration:

```groovy
gradle.beforeProject { p ->
    if (p.path == ':app') {
        p.plugins.withId('com.android.application') {
            p.android.buildTypes.named('debug').configure { debuggable = false }
        }
    }
}
```

The app [debuggable manifest flag](https://developer.android.com/guide/topics/manifest/application-element#debug) and the native process dumpability are checked separately. Add `-e expectNonDebuggable true` to require both a false application flag and `PR_GET_DUMPABLE == 0`; the collector never sets dumpability. A debug-only pass is insufficient to prove ordinary release-app visibility.

Run the installed fixture:

```sh
adb -s "$AVD_SERIAL" shell am instrument -w -r \
  -e class com.eltavine.duckdetector.features.zygisk.data.ZygiskAtexitRuntimeTest \
  -e environment control \
  -e expectNoAtexitEvidence true \
  com.eltavine.duckdetector.test/androidx.test.runner.AndroidJUnitRunner
adb -s "$AVD_SERIAL" logcat -d -s AtexitRuntime:I
```

Omit `expectNoAtexitEvidence` for injection environments; pass `expectAtexitEvidence=true` only when a controlled positive is expected. Each test collects twice and checks evaluated table coverage. Framework installation alone does not guarantee that an app receives an injected module or that any table residue survives.

## Pinned inputs

| Input | Revision / build | SHA-256 |
|---|---|---|
| Supplied Zygisk Next | 1.5.2 (864-a4a72ce-release) | ce50b13fecb9e4456db69ef17b715f7cfbc094004dd9f30f7d6348dfab619a96 |
| ReZygisk default-branch CI | 1.0.0 (552-b5aa415-release), [run 38174785673](https://github.com/PerformanC/ReZygisk/actions/runs/38174785673) | 41085b35c44b4c9d8a6b9b48ddc7f7139bc968d05fc67d4c5f716ce7fece8384 |
| NeoZygisk default-branch CI | 2.4 (295-d161f31-release), [run 39921933576](https://github.com/JingMatrix/NeoZygisk/actions/runs/39921933576) | 5d6cc18f2cf5c415fb4a8119039457d8da4e4efbec3735a683d491f2dc8f1f0c |
| Supplied zDefend kit (3) | Discovery rule #697852 v12; engine and 26 encrypted assets match kit (2) | 884ffeb3b8f01456a451657792d2cdbabbdb08f6f736950e332024c1876f8c0c |

The CI packages are the latest successful push builds of main/master resolved on 2026-10-25, not the latest tagged releases or unrelated experimental branches. Raw Actions archive hashes match GitHub's artifact digests. Only one injection framework is enabled at a time; Magisk's built-in Zygisk is disabled.

The AVD uses `google/sdk_gphone64_arm64/emu64a:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys`, API 36, security patch 2025-07-05, 4 KiB pages, and kernel `6.6.66-android15-8-gd0c43a640eab-ab13812146-4k`. Module administration uses Magisk 30.7. A copied ramdisk is patched for the disposable test environment; the installed SDK system image is not overwritten. No physical-device or vendor-layout coverage is implied.

## Observed results (2026-10-25)

All eight cases passed two scans with the same non-debuggable APK built from source revision [0be879a0](https://github.com/eltavine/Duck-Detector-Refactoring/commit/0be879a072d01fe8be418cc1399c2d74d69bdd6c). Each scan recorded UID 10213, `u:r:untrusted_app:s0:c213,c256,c512,c768`, `debuggable=false`, `dumpable=0` and table state `COLLECTED`. SELinux remained Enforcing. Cleared-entry and anchored-gap counts were zero throughout.

| Environment | Controlled resident memfd payload | Entries | Anonymous callbacks per scan |
|---|---|---:|---:|
| Stock AVD | No | 1547 | 0 |
| Magisk only, built-in Zygisk disabled | No | 1547 | 0 |
| Zygisk Next 1.5.2 / 864-a4a72ce | No | 1547 | 0 |
| Zygisk Next 1.5.2 / 864-a4a72ce | Yes | 1548 | 1 |
| ReZygisk CI 552-b5aa415 | No | 1547 | 0 |
| ReZygisk CI 552-b5aa415 | Yes | 1548 | 1 |
| NeoZygisk CI 295-d161f31 | No | 1547 | 0 |
| NeoZygisk CI 295-d161f31 | Yes | 1548 | 1 |

Each positive fixture logged successful libc registration and payload loading before specialization. Both scans then resolved handler 1534 into `/memfd:duck-atexit-fixture (deleted)` and emitted warning-level atexit evidence. Framework/module enable state was checked outside the app between reboots; the positive pre-specialize callbacks confirm active injection. The Magisk-only control had no Zygisk daemon. Entry counts and indices describe this AVD/application build, not portable expected constants.

The framework-only negatives demonstrate that enabling these builds does not necessarily leave this residue. The positives establish visibility of a controlled surviving callback, not framework identification, version attribution, arbitrary module unloading or native gap specificity. Runtime-gap interpretation has synthetic regression coverage; no actual framework-produced gap was observed. Missing local libc symbols, unsupported layouts and platform restrictions still reduce coverage on other devices.

Test artifact SHA-256 values:

| Artifact | SHA-256 |
|---|---|
| Non-debuggable host APK | 2b9933952b8eda5d151c95804a7a57054ef573324302517cca5bc1779d7ca5ec |
| Instrumentation APK | 3574db2d3280c5fe41a4461666a3723ce6006976cdcf26f76f6e725c0f6f876a |
| ARM64 fixture module library | 5f70a9390f8efee49339e554bef558df2054592eae936177baf187ea65339bc1 |
| Embedded payload library | 0e77a7511386df7a4a7ac4f94dc44280c2ef88885322b8997687c0ff5089b35f |

The project validation passed 1715 JVM tests, all four ABI builds, app lint, architecture/contract checks, buildHealth, SDK AAR publication/verification and a standalone SDK consumer build. Host-native evidence and memory-copy fixtures passed with undefined-behavior checks, including exact/below-60% clearing and 64-bit inode parsing. The ELF fixture passed alias, mutex-overlap and alignment regressions as an ARM64 Android executable because this macOS host has no system `<elf.h>`; the memory-copy fixture also passed on Android with dumpability set to zero by the test executable and verified unchanged by the reader. Payload regressions reject missing/contradictory counts and preserve typed evidence when aggregate counters are zero. The application collector never changes dumpability.

```sh
./gradlew unitTest :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug \
  :sdk:aar:publish :sdk:aar:verifySdkAar buildHealth --continue --max-workers=4
./gradlew -p samples/sdk-consumer assembleDebug --max-workers=2
python3 feature/zygisk/data/src/test/python/test_atexit_host_native.py
python3 feature/zygisk/data/src/test/python/test_loader_path_host_native.py
```

## Controlled resident callback

`data/src/test/fixtures/atexit_module.cpp` is an optional AVD-only module. It loads an embedded small shared object through `android_dlopen_ext` and a memfd only in the detector app; that object registers a no-op destructor callback and remains resident. Embedding avoids dependence on privileged module-directory file opening. Logcat's `AtexitFixture` tag must confirm that the pre-specialize callback ran, the payload loaded, and registration returned zero through libc. Enabling a module without these preconditions is not a valid positive test. The file-descriptor flag is specified in [Android 16 dlext.h](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r1/libc/include/android/dlext.h). It is not bundled into the app or SDK. Build it against the separately obtained public Zygisk v4 header at [7bb941ac](https://github.com/topjohnwu/zygisk-module-sample/blob/7bb941ac8edfcffd1d23761e401c45ca95409dc1/module/jni/zygisk.hpp); retain that header's license when obtaining it. No external SDK header is vendored here.

```sh
"$NDK_TOOLCHAIN/aarch64-linux-android30-clang++" \
  -shared -fPIC -fno-exceptions -fno-rtti -static-libstdc++ \
  -Wl,-z,max-page-size=16384 \
  feature/zygisk/data/src/test/fixtures/atexit_payload.cpp -ldl -llog -o callback_payload.so
python3 - <<'PY'
from pathlib import Path
payload = Path('callback_payload.so').read_bytes()
Path('payload_bytes.h').write_text(
    'static constexpr unsigned char kPayload[] = {' +
    ','.join(str(byte) for byte in payload) + '};\n')
PY
"$NDK_TOOLCHAIN/aarch64-linux-android30-clang++" \
  -std=c++17 -shared -fPIC -fno-exceptions -fno-rtti -static-libstdc++ \
  -Wl,-z,max-page-size=16384 -I "$ZYGISK_V4_INCLUDE" -I . \
  feature/zygisk/data/src/test/fixtures/atexit_module.cpp -ldl -llog -o arm64-v8a.so
```

Package the module as `zygisk/arm64-v8a.so` in a normal Magisk module ZIP with a unique module.prop and skip_mount, install only on the disposable AVD, and reboot. Record both the framework-only and controlled-callback cases. A file-backed callback is not an anonymous-callback positive; the resident memfd payload specifically exercises that branch. This fixture checks whether callbacks in injected executable mappings are observable; it does not validate arbitrary module unloading or gap specificity.

The ELF malformed-image fixture can also be compiled with the NDK from `libc_objects.cpp` and `data/src/test/native/atexit_objects_test.cpp` and run on the AVD. Host suites use undefined-behavior checks; the ELF host fixture requires a host `<elf.h>`, so macOS runs that fixture on Android instead.
