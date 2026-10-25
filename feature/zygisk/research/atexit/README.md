# Exit-handler AVD comparison

## Reproduction boundary

Use an ARM64 Android 16 AVD with a clean control and separate disposable Magisk module state. Collection itself runs inside the installed host as an ordinary app, and the instrumentation asserts an app UID >=10000 and an `untrusted_app` SELinux domain. Root/adbd administration is used only to prepare module environments and inspect their running state; the collector does not invoke su, enumerate root-only module directories or read another process. Keep SELinux enforcing.

Build `:app:assembleDebug` and `:app:assembleDebugAndroidTest`, install the APKs named by each output-metadata.json, and preverify both packages with `cmd package compile -m verify -f` if the first instrumentation launch spends its startup deadline in ART DEX verification.

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

The CI packages are the latest successful push builds of main/master resolved on 2026-10-25, not the latest tagged releases or unrelated experimental branches. Raw Actions archive hashes match GitHub's artifact digests. Only one injection framework is enabled at a time; Magisk's built-in Zygisk is disabled.

The AVD uses `google/sdk_gphone64_arm64/emu64a:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys`, API 36, security patch 2025-07-05, 4 KiB pages, and kernel `6.6.66-android15-8-gd0c43a640eab-ab13812146-4k`. Module administration uses Magisk 30.7. A copied ramdisk is patched for the disposable test environment; the installed SDK system image is not overwritten. No physical-device or vendor-layout coverage is implied.

## Controlled resident callback

`data/src/test/fixtures/atexit_module.cpp` is an optional AVD-only module. It loads a small shared object through `android_dlopen_ext` and a memfd only in the detector app; that object registers a no-op destructor callback and remains resident. The file-descriptor flag is specified in [Android 16 dlext.h](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r1/libc/include/android/dlext.h). It is not bundled into the app or SDK. Build it against the separately obtained public Zygisk v4 header at [7bb941ac](https://github.com/topjohnwu/zygisk-module-sample/blob/7bb941ac8edfcffd1d23761e401c45ca95409dc1/module/jni/zygisk.hpp); retain that header's license when obtaining it. No external SDK header is vendored here.

```sh
"$NDK_TOOLCHAIN/aarch64-linux-android30-clang++" \
  -std=c++17 -shared -fPIC -fno-exceptions -fno-rtti -static-libstdc++ \
  -Wl,-z,max-page-size=16384 -I "$ZYGISK_V4_INCLUDE" \
  feature/zygisk/data/src/test/fixtures/atexit_module.cpp -ldl -o arm64-v8a.so
"$NDK_TOOLCHAIN/aarch64-linux-android30-clang++" \
  -shared -fPIC -fno-exceptions -fno-rtti -static-libstdc++ \
  -Wl,-z,max-page-size=16384 \
  feature/zygisk/data/src/test/fixtures/atexit_payload.cpp -o callback_payload.so
```

Package the module as `zygisk/arm64-v8a.so` and the payload as `callback_payload.so` at the archive root in a normal Magisk module ZIP with a unique module.prop and skip_mount, install only on the disposable AVD, and reboot. Record both the framework-only and controlled-callback cases. The initial direct-callback fixture was file-backed under ReZygisk, added one table entry and triggered the existing executable-map observation without an anonymous-callback finding. The memfd payload is a controlled positive for the new branch. This fixture checks whether callbacks in injected executable mappings are observable; it does not validate arbitrary module unloading or gap specificity.

The ELF malformed-image fixture can also be compiled with the NDK from `libc_objects.cpp` and `data/src/test/native/atexit_objects_test.cpp` and run on the AVD. Host suites use undefined-behavior checks; the ELF host fixture requires a host `<elf.h>`, so macOS runs that fixture on Android instead.
