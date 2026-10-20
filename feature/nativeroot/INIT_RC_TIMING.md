# Residual init.rc hook timing experiment

The question is whether an arm64 app can observe a thread-name/file-name timing interaction consistent with KernelSU's retained early-boot fstat hook. This experiment does not establish that KernelSU is installed or absent.

## Source and scope

The reviewed implementation is KernelSU parent commit `b609757fad4441b88e73966c5dc12e4788be9d3b`, immediately before [5486a0e](https://github.com/tiann/KernelSU/commit/5486a0e27d5b417dd6769ebca955016d513c7584). In `kernel/runtime/ksud_integration.c`:

- `ksu_ksud_init` directly installs read/fstat syscall-table hooks.
- `is_init_rc` checks comm `init`, regular-file type, short name `init.rc`, then a 256-byte d_path result against `/system/etc/init/hw/init.rc`.
- `ksu_install_rc_hook` calls `stop_init_rc_hook` only after a successful match. A bind-mounted source with another short name can prevent this match and retain the hooks.
- `ksu_sys_fstat` invokes this predicate even for a private app file. That file cannot match the final system path.
- `kernel/core/init.c` skips `ksu_ksud_init` in late-load mode.

ACK `android14-6.1` at `bb5a6085be4a3639bc50ef4ec04309dc723a0663` is the kernel semantics reference, not a claim about every device kernel. Its `kernel/sys.c` implements the calling task's PR_SET_NAME/PR_GET_NAME; `fs/stat.c` obtains file attributes from the descriptor; `fs/d_path.c` walks the dentry/mount path; `fs/namespace.c` uses the source dentry for bind mounts. Bionic `android-16.0.0_r2/libc/SYSCALLS.TXT` maps lp64 fstat directly to fstat. The sampler uses the NDK's arm64 syscall number and stat structure, not a copied syscall number or an architecture timer register.

Bionic `android-16.0.0_r2/libc/SECCOMP_BLOCKLIST_APP.TXT` does not block fstat, prctl, sched affinity or getcpu from the SYSCALLS.TXT allowlist; `libc/bionic/sched_getcpu.cpp` uses the latter for CPU checks. This establishes the standard Android app policy path, not compatibility with arbitrary SDK-host seccomp filters. Permission or affinity errors invalidate the run and retain their errno.

## Measurement and ownership

The data module owns collection and a feature-specific JNI bridge. The domain module owns the pure analysis; presentation renders its typed observation. No dependency or shared mutable state is added.

A fresh 0700 directory under the app's canonical cache directory contains two independent 0600 regular files, `data.rc` and `init.rc`. Android's SELinux policy never allows an untrusted app to create a hard link, so the control cannot share the target's inode; instead both files must expose the same device, mode, size and ownership, each with a link count of one and a distinct inode. The reviewed hook compares comm, file type, dentry name and d_path, never the inode. Every fstat result must match its own file's inode, device, mode, size, ownership and link count; an intermediate mismatch invalidates the batch even if the last call would match again. These checks contribute the same baseline work to all four conditions. Paths at least 256 bytes long are rejected because the reviewed hook's path buffer has that size. The experiment never opens the system init.rc or changes a mount.

A dedicated worker changes only its own comm and pins itself to one already permitted CPU. Every batch verifies name readback, the singleton affinity mask and actual CPU before/after sampling. The explicit `std::launch::async` policy forbids deferred execution on the caller; completion is awaited before caller-owned descriptors, results or inputs can be released, including when the worker throws. This follows the [C++ async completion contract](https://eel.is/c++draft/futures.async), implemented by the bundled NDK libc++ `future` header's `__async_assoc_state` and `__make_async_assoc_state`; no new runtime dependency is introduced. The caller's comm and affinity are untouched. Files, descriptors and directory are removed on success and failure. Cleanup failure invalidates an otherwise completed run and retains its errno.

Conditions are normal comm `duck` / target comm `init`, crossed with control / target filename. Each of 32 rounds collects four batches of 128 raw fstat calls. The four Williams orders are `0132`, `1203`, `2310`, `3021`: each condition occupies every position and each directed within-round predecessor pair occurs once per cycle. Warm-up is outside the retained samples. Name changes, CPU checks, allocation and formatting are outside timed batches. CLOCK_MONOTONIC measures complete batches. A one-second cooperative budget bounds additional work between batches; it cannot interrupt a blocked kernel syscall. Coroutine cancellation is checked before and after collection; no native worker outlives the call.

For each round, the per-call contrast is:

```text
(init comm, init.rc) - (init comm, data.rc)
  - (duck comm, init.rc) + (duck comm, data.rc)
```

Analysis reports the median contrast, median absolute deviation (MAD), positive-round count and four order-specific medians. Wire validation and typed analysis share a necessary budget invariant: the sum of retained batch durations must be less than one second; a packet whose individual batches fit but whose total cannot fit the experiment remains invalid. Warm-up and other overhead also consume the native budget. A descriptive repeatability rule requires at least 28/32 positive rounds, at least 6/8 positive rounds per order, positive medians in both halves, and a median larger than three MADs. These are provisional experiment quality rules, not calibrated detection thresholds. No independence assumption, p-value or false-positive probability is asserted. A completed experiment that does not meet this rule reports no repeatable interaction, not a clean device. Missing/invalid data never contributes zero-valued timing samples.

## Reproducible verification

- `python3 feature/nativeroot/data/src/test/native/test_initrc_timing_probe.py`: production sampler with injected syscall/name/clock/CPU/affinity failures and worker exceptions; balanced order, transient metadata mismatches, budget, cleanup and caller state isolation.
- `./gradlew :feature:nativeroot:domain:unitTest :feature:nativeroot:data:unitTest :feature:nativeroot:presentation:unitTest`: contrast analysis, corrupted payloads, presentation and evidence limits.
- `./gradlew unitTest :app:assembleDebug :app:lintDebug`: integration, all supported build ABIs and Android lint. Non-arm64 collectors return unsupported.

Physical-device calibration remains outstanding. Before changing evidence strength, record Android/API, kernel revision/configuration, ABI, SoC/OEM, SELinux domain, exact KernelSU SHA/load mode, module set, tracing state, CPU and raw round data. Compare at least:

| KernelSU state | Boot init.rc | Expected scope |
| --- | --- | --- |
| Absent, otherwise same kernel | Original | Negative control; measure rather than assume zero contrast |
| Parent b609757, early load | Original and successfully recognized | Hooks normally removed; no coverage for this leak |
| Parent b609757, early load | Differently named source bind-mounted before parsing | Candidate retained-hook positive; confirm hook state with privileged instrumentation |
| Fixed 5486a0e, early load | Same bind mount | Recognition/retraction control |
| Parent, late load | Either | Hooks not installed; outside positive scope |
| Any of the above | Under CPU/IO load and enabled tracing | Noise and confounding controls |

An absence of interaction cannot exclude KernelSU, a patched fork, removed hooks, hidden observations or an effect smaller than the noise. A repeatable interaction is not unique to KernelSU: other comm-aware instrumentation can reproduce it. The four batches share a mechanism and are controls within one experiment, not four independent root indicators.
