# KernelSU prctl Timing

## Scope

This is supporting timing evidence within Native Root, not another detector, a root identification, or an exclusion test. Ordinary Native Root scans run it automatically when applicable, after the optional SRCU experiment and before the throne-hunt stimulus. No preload or new consent surface is introduced. Previous observations are never reused.

Only ordinary app UIDs (app-id 10000 through 19999, with equal real/effective UID) in a 64-bit AArch64 process are eligible. Other architectures return unsupported without issuing the timing calls. A private, non-exported, same-UID `:ksu_timing` service contains failures; it is not isolated or started through app_zygote. Binder carries a bounded binary summary of at most 16 cores with three rounds each, never raw vectors.

## Native Windows

Every measurement uses raw AArch64 syscall 167 (`prctl`) and `CNTVCT_EL0`, with ISB around the counter reads. Raw `-EINTR` retries remain inside the timed window. Each vector has 10000 samples, one completed syscall per sample excluding retries. Values retain their unsigned 64-bit representation. They are virtual counter ticks, not CPU cycles or nanoseconds; `CNTFRQ_EL0` is recorded separately. Counter traps cannot be caught as ordinary JNI exceptions.

The single preflight window uses `(0xDEADBEEF, 1, "/data/data/com.android.keychain", 0, 0, 0)`. Its exact frequency table must contain 10000 observations, at most 750 bins, and minimum tick value at most 135. Empty, duplicate or malformed tables fail closed. These are empirical profile constants, not architecture guarantees or calibrated device-independent limits. The preflight binds the first working CPU in the current allowed affinity mask.

Main windows use six vectors and three argument sets:

| Name | Six syscall arguments |
| --- | --- |
| A | `(0xDEADBEEE, 7, 0, 0, 0, 0)` |
| B | `(0xDEADBEEF, 7, 0, 0, 0, 0)` |
| C | `(0xDEADBEED, 7, 0, 0, 0, 0)` |

For every index the order is `C -> V3, A -> V0, C -> V4, B -> V1, C -> V5, A -> V2`. Allocation, JNI, Binder, logging and classification are outside the timed interval. Counter reads and SVC live in the same translation unit. Each window uses a disposable pthread with verified nice 19 (Linux clamps a request of 20). Destroying that thread avoids trying to raise its priority again without privilege or changing a reused coroutine thread. Saved affinity is restored and checked; a cleanup failure invalidates an otherwise positive result.

The preflight is not merely a read-only version query. In reviewed [KernelSU v0.9.5](https://github.com/tiann/KernelSU/blob/v0.9.5/kernel/ksu.h), command 1 is `BECOME_MANAGER`, command 7 is `REPORT_EVENT`; command 0, not 1, is `GRANT_ROOT`. The [v0.9.5 handler](https://github.com/tiann/KernelSU/blob/v0.9.5/kernel/core_hook.c) and [KernelSU-Next v1.0.2 handler](https://github.com/KernelSU-Next/KernelSU-Next/blob/v1.0.2/kernel/core_hook.c) gate privileged paths. The [v0.6.9 handler](https://github.com/tiann/KernelSU/blob/v0.6.9/kernel/core_hook.c) also checks manager directory ownership against the caller UID. The keychain directory is not owned by an ordinary third-party app. For these reviewed handlers, command 7 requires root and event zero has no matching action. These observations do not prove harmlessness for arbitrary modified handlers or forks. UID gating cannot establish the semantics of an unknown kernel hook.

## Classifiers

For each aligned triple `(V0[i], V1[i], V2[i])`, let `m` and `M` be its unsigned minimum and maximum. A feature is high only when `value - m > M - value`. Equality and exact midpoints are zero. Let `z0, z1, z2` count zero features and `j` count the `010` pattern. Counts below 50 are discarded as a whole. The distance classifier requires all of:

- `z0 > z1` and `z2 > z1`;
- `abs(z2 - z0) <= 800`;
- retained `j >= 1800`;
- `r = floor((z0 + z2) / 2) > z1` and `abs(r - z1) >= 2500`.

Exact tick histograms `H0..H5` contain no fixed bin array or bucketing. The reference histogram is `R(k) = floor((H0(k) + H2(k)) / 2)` with missing bins treated as zero. Cosine uses the union of bins where either operand has count strictly greater than 500. Its denominator is `max(1, sqrt(sum(a*a)) * sqrt(sum(b*b)))`. Required pairs and thresholds are:

| Pair | Requirement |
| --- | --- |
| H0, H2 | cosine >= 0.98 |
| R, H1 | cosine <= 0.94 |
| H2, H3 | cosine >= 0.99 |
| H3, H4 | cosine >= 0.99 |
| H4, H5 | cosine >= 0.99 |

Mean keys are the union where `R(k) > 100` or `H1(k) > 100`. Weighted products and sums wrap as unsigned 64-bit integers before conversion to double. The target mean must exceed the reference mean. Empty support gives NaN and cannot match. A round is positive only when both classifiers match.

## Completion And Failure

CPU directories are enumerated contiguously from 0 through 15, stopping at the first confirmed missing directory. Other filesystem errors are not absence. Each requested CPU is bound and read back, and its actual CPU is checked before and after sampling. A negative round ends that CPU; three consecutive positive rounds on the same CPU confirm the pattern and end collection. Hits on different CPUs never accumulate.

Interactive state is checked before and after every native window, including the single preflight. Noninteractive does not mean screen-off: Android defines `isInteractive` independently. No wakeup or cached screen state is used. The experiment checks a 40-second deadline between windows; an independent worker watchdog kills only the carrier after 45 seconds, and the host has a 50-second bound. A stuck native window is contained by the watchdog, not coroutine cancellation. Cancellation unbinds; the worker stops at its next window boundary. Late replies are not reused.

Failure states preserve preflight results, attempted CPUs, per-round classifier metrics, counter frequency and known cleanup state. Worker disconnection means `WORKER_DIED`; it does not establish SIGILL, seccomp or watchdog as the cause. Deadline, cancellation, transport failure and cleanup failure cannot carry a confirmed verdict. A noninteractive/partial result can retain already complete same-core evidence but cannot support an absence claim. `NOT_OBSERVED` requires full enumerated coverage with valid negative endings and verified cleanup. A positive is WARNING only and never adds a KernelSU/root family flag.

## Validation Limits

Host tests compile the production sampler with fake counter/SVC/affinity/priority functions. They exercise order, preflight arguments, EINTR, UID rejection, binding, CPU mismatch, timer failure and restoration failure without issuing real magic calls. JVM tests cover exact histograms, 49 configured boundary cases, strict 100/101 and 500/501 limits, unsigned wrap, NaN, conjunction, per-core orchestration, bounded decoding, UI projection and report export.

No device sampling, runtime cost measurement, clean/rooted comparison, false-positive/false-negative study or counter-frequency calibration has been performed. Compilation does not establish that EL0 counter access works on a device. Vendor seccomp/security hooks, counter traps, hotplug, virtualization and system load remain unknowns. Thresholds must not be presented as universal Android invariants.
