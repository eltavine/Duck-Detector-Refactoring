# KernelSU prctl Timing

## Scope

This is supporting timing evidence within Native Root, not another detector, a root identification, or an exclusion test. Ordinary Native Root scans run it automatically when applicable, after the optional SRCU experiment and before the throne-hunt stimulus. No preload or new consent surface is introduced. Previous observations are never reused.

Only ordinary app UIDs (app-id 10000 through 19999, with equal real/effective UID) in a 64-bit AArch64 process are eligible. Other architectures return unsupported without issuing the timing calls. A private, non-exported, same-UID `:ksu_timing` service contains failures; it is not isolated or started through app_zygote. Binder carries a binary summary bounded to 192 KiB and at most 16 cores with one preflight and three rounds each, never raw vectors. Private carrier/JNI protocol version 2 rejects older summaries because they lack outcome, eligibility and classifier-support evidence.

## Native Windows

Every measurement uses raw AArch64 syscall 167 (`prctl`) and `CNTVCT_EL0`, with ISB around the counter reads. Raw `-EINTR` retries remain inside the timed window, with at most three retries per sample. Each vector has 10000 samples, recording the final syscall outcome even when the retry bound is exhausted. Values retain their unsigned 64-bit representation. They are virtual counter ticks, not CPU cycles or nanoseconds; `CNTFRQ_EL0` is recorded separately. Counter traps cannot be caught as ordinary JNI exceptions.

Each eligible candidate CPU gets its own preflight window using `(0xDEADBEEF, 1, "/data/data/com.android.keychain", 0, 0, 0)`, bound to that requested CPU. Its exact frequency table must contain 10000 observations, at most 750 bins, and a minimum of at most 135 counter ticks. The original tick gate is preserved independently for each CPU; a larger minimum produces `EXCESSIVE_MINIMUM` and skips only that CPU's main windows. Empty, duplicate or malformed tables also fail closed for that CPU; other CPUs remain eligible for their own preflight. Rejected CPUs cannot supply a negative result. Both bounds are empirical applicability filters, not platform guarantees. Minimum ticks and counter frequency remain diagnostic evidence; the cutoff is not frequency-normalized and its applicability across devices still requires validation.

Main windows use six vectors and three argument sets:

| Name | Six syscall arguments |
| --- | --- |
| A | `(0xDEADBEEE, 7, 0, 0, 0, 0)` |
| B | `(0xDEADBEEF, 7, 0, 0, 0, 0)` |
| C | `(0xDEADBEED, 7, 0, 0, 0, 0)` |

For every index the order is `C -> V3, A -> V0, C -> V4, B -> V1, C -> V5, A -> V2`. Allocation, JNI, Binder, logging, outcome aggregation and classification are outside the timed interval. The retry loop and its counter remain inside it. Counter reads and SVC live in the same translation unit. Each window uses a disposable pthread with verified nice 19 (Linux clamps a request of 20). Destroying that thread avoids trying to raise its priority again without privilege or changing a reused coroutine thread. Saved affinity is restored and checked; a cleanup failure invalidates an otherwise positive result.

The preflight is not merely a read-only version query. In reviewed [KernelSU v0.9.5](https://github.com/tiann/KernelSU/blob/v0.9.5/kernel/ksu.h), command 1 is `BECOME_MANAGER`, command 7 is `REPORT_EVENT`; command 0, not 1, is `GRANT_ROOT`. The [v0.9.5 handler](https://github.com/tiann/KernelSU/blob/v0.9.5/kernel/core_hook.c) and [KernelSU-Next v1.0.2 handler](https://github.com/KernelSU-Next/KernelSU-Next/blob/v1.0.2/kernel/core_hook.c) gate privileged paths. The [v0.6.9 handler](https://github.com/tiann/KernelSU/blob/v0.6.9/kernel/core_hook.c) also checks manager directory ownership against the caller UID. The keychain directory is not owned by an ordinary third-party app. For these reviewed handlers, command 7 requires root and event zero has no matching action. These observations do not prove harmlessness for arbitrary modified handlers or forks. UID gating cannot establish the semantics of an unknown kernel hook.

Each vector retains at most eight distinct final raw return codes and their sample counts, an overflow count for additional codes, retried-sample count, total retries, maximum retries, and retry-limit sample count. Summaries remain available even if a later CPU or cleanup check rejects the window. Every preflight/main vector must end in raw `-EINVAL` for all 10000 samples with no retries before timing can contribute either a match or a valid non-match. Any success, other errno, mixed outcomes, overflow or retry produces `OUTCOME_CONTAMINATED`; it is not a timing negative. This conservative rule may discard usable timing evidence on unusual handlers. Identical return codes do not prove identical kernel paths.

## Classifiers

For each aligned triple `(V0[i], V1[i], V2[i])`, let `m` and `M` be its unsigned minimum and maximum. A feature is high only when `value - m > M - value`. Equality and exact midpoints are zero. Let `z0, z1, z2` count zero features and `j` count the `010` pattern. Counts below 50 are discarded as a whole. The distance classifier requires all of:

- `z0 > z1` and `z2 > z1`;
- `abs(z2 - z0) <= 800`;
- retained `j >= 1800`;
- `r = floor((z0 + z2) / 2) > z1` and `abs(r - z1) >= 2500`.

Exact tick histograms `H0..H5` contain no fixed bin array or bucketing. The reference histogram is `R(k) = floor((H0(k) + H2(k)) / 2)` with missing bins treated as zero. Cosine uses the union of bins where either operand has count strictly greater than 500. Its denominator is `sqrt(sum(a*a)) * sqrt(sum(b*b))`; a zero norm yields an unavailable (NaN) score. Required pairs and thresholds are:

| Pair | Requirement |
| --- | --- |
| H0, H2 | cosine >= 0.98 |
| R, H1 | cosine <= 0.94 |
| H2, H3 | cosine >= 0.99 |
| H3, H4 | cosine >= 0.99 |
| H4, H5 | cosine >= 0.99 |

Mean keys are the union where `R(k) > 100` or `H1(k) > 100`. Weighted products and sums wrap as unsigned 64-bit integers before conversion to double. The target mean must exceed the reference mean. Empty support gives NaN. All five cosine pairs and the mean pair report retained bin count and retained sample mass for both operands. A classifier is `VALID` only when every pair retains at least 5001 samples from each operand and all metrics are finite. Missing, empty or minority support is `INSUFFICIENT_SUPPORT`, and nonfinite metrics are explicitly invalid. An invalid round ends that CPU inconclusively and cannot supply a negative ending.

The 500/100 cutoffs select exact-tick modes exceeding 5%/1% of a 10000-sample vector; they are empirical modal filters, not calibrated time limits. Their applicability requires sufficiently concentrated exact-tick distributions in the observed window. Counter resolution/frequency and system noise can spread samples below the filters, so CNTFRQ alone does not establish applicability. The 5001-sample rule is a conservative coverage requirement: a retained minority cannot stand in for the measured distribution. It does not establish statistical accuracy or calibrate the existing matching thresholds. A round is positive only when support is valid and both classifiers match.

## Completion And Failure

CPU inventory comes from `/sys/devices/system/cpu/present`, online state from `/sys/devices/system/cpu/online`, and the carrier thread's effective allowed set from `sched_getaffinity(0)`. Sparse IDs and ranges are preserved up to the fixed 1024-bit affinity capacity; malformed, inaccessible or out-of-range inventories are unavailable, not empty inventories. The first 16 present IDs form the bounded candidate budget. Offline CPUs, CPUs outside effective affinity/cpuset, and IDs beyond the budget remain in the report with exclusion reasons. They prevent complete negative coverage.

Capture an initial snapshot, before/after snapshots around each native window, and a final snapshot. Each disposable sampling pthread also reports its own allowed mask before binding, so inheritance differences cannot be silently hidden by a carrier-thread snapshot. Bind the requested CPU, read affinity back and verify actual CPU before/after sampling. A before/after change, worker-mask mismatch, or eligibility change between rounds on the same CPU produces `ELIGIBILITY_CHANGED` and ends that CPU inconclusively. Other candidate CPUs can still run. Any observed snapshot change prevents a complete negative. These sequential snapshots do not lock hotplug or cgroups and cannot exclude a transient change that has reverted between reads.

A valid negative round ends that CPU; three consecutive valid positive rounds on the same CPU confirm the pattern and end collection. Hits on different CPUs never accumulate. The report separates present, online, effective allowed, sampled and completed CPUs, per-CPU preflight and rejection status, and per-window snapshots.

Interactive state is checked before and after every native window, including each CPU preflight. Noninteractive does not mean screen-off: Android defines `isInteractive` independently. No wakeup or cached screen state is used. The experiment checks a 40-second deadline between windows; an independent worker watchdog kills only the carrier after 45 seconds, and the host has a 50-second bound. A stuck native window is contained by the watchdog, not coroutine cancellation. Cancellation unbinds; the worker stops at its next window boundary. Late replies are not reused.

Failure states preserve per-CPU preflight results, attempted CPUs, per-window eligibility and syscall summaries, retained histogram support, classifier validity, counter frequency and known cleanup state. Worker disconnection means `WORKER_DIED`; it does not establish SIGILL, seccomp or watchdog as the cause. Deadline, cancellation, transport failure and cleanup failure cannot carry a confirmed verdict. A noninteractive/partial result can retain already complete same-core evidence but cannot support an absence claim. `NOT_OBSERVED` explicitly means coverage of all present CPUs in stable observed snapshots, with valid negative endings and verified cleanup. Successful sampling of every eligible CPU still remains `PARTIAL`/inconclusive if any present CPU was excluded, unavailable or outside the budget. A positive is WARNING only and never adds a KernelSU/root family flag.

## Validation Limits

Host tests compile the production sampler with fake counter/SVC/affinity/priority functions. They exercise order, per-CPU preflight arguments, bounded EINTR retries and exhaustion, distinct syscall outcomes, bounded return-code histograms, UID rejection, binding, CPU mismatch, timer failure and restoration failure without issuing real magic calls. JVM tests cover exact histograms, configured mathematical boundaries, strict 100/101 and 500/501 limits, support-mass boundaries, unsigned wrap, invalid metrics, conjunction, independent per-CPU preflight rejection, hotplug/cpuset snapshots, excluded CPUs, outcome contamination, bounded decoding, UI projection and report export.

Reproduce the focused checks with `python3 feature/nativeroot/data/src/test/native/test_ksu_timing_probe.py` and `./gradlew :feature:nativeroot:domain:test :feature:nativeroot:data:testDebugUnitTest :feature:nativeroot:presentation:test`.

## Platform References

- [Android cgroups/task profiles](https://source.android.com/docs/core/perf/cgroups): Android and vendor task profiles can restrict threads/processes; no particular cgroup filesystem layout is assumed here.
- ACK android12-5.10 at [`b68a49c9`](https://android.googlesource.com/kernel/common/+/b68a49c9f248ee01e80696efebab7af94919d802/) and android14-6.1 at [`2f0d8641`](https://android.googlesource.com/kernel/common/+/2f0d864181b9acf801e9b51c345e11b6156b767a/): `drivers/base/cpu.c` exposes separate online/present masks; `kernel/sched/core.c` implements effective affinity and cpuset restrictions; `kernel/sys.c` calls `security_task_prctl` before its option switch and rejects unknown options with EINVAL. These reviewed branches establish the model, not identical behavior on every vendor kernel. Runtime capture and explicit failures remain necessary.
- [Bionic Android 14 `sched_getaffinity.cpp`](https://android.googlesource.com/platform/bionic/+/android-14.0.0_r1/libc/bionic/sched_getaffinity.cpp): the libc adapter clears mask bytes not written by the kernel and returns zero on success; the native bridge uses this libc contract rather than raw syscall return length.

No device sampling, runtime cost measurement, clean/rooted comparison, false-positive/false-negative study or counter-frequency calibration has been performed. Compilation does not establish that EL0 counter access works on a device. Vendor seccomp/security hooks, counter traps, hotplug, virtualization and system load remain unknowns. Thresholds must not be presented as universal Android invariants.
