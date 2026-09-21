/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "virtualization/honeypot_traps.h"

#include "common/payload_codec.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace duckdetector::virtualization {

    namespace {

        std::string encode_value(const std::string &value) {
            return common::escape_payload_value(value);
        }

        long long monotonic_ns() {
            struct timespec now{};
            clock_gettime(CLOCK_MONOTONIC, &now);
            return static_cast<long long>(now.tv_sec) * 1000000000LL + now.tv_nsec;
        }

        /**
         * Relative spread of the samples, or nothing when no spread can be expressed.
         *
         * The empty result is not the same as a coefficient of zero and callers must not
         * collapse the two. A zero mean means the samples carry no elapsed time at all, so
         * there is nothing to take a ratio against; reporting 0.0 for that case would hand
         * back the most uniform value the scale has for a measurement that never happened.
         */
        std::optional<double> coefficient_of_variation(const std::vector<long long> &samples) {
            if (samples.empty()) {
                return std::nullopt;
            }
            const double mean = std::accumulate(samples.begin(), samples.end(), 0.0) /
                                static_cast<double>(samples.size());
            if (mean <= 0.0) {
                return std::nullopt;
            }
            double variance = 0.0;
            for (const auto sample: samples) {
                const double delta = static_cast<double>(sample) - mean;
                variance += delta * delta;
            }
            variance /= static_cast<double>(samples.size());
            return sqrt(variance) / mean;
        }

        TrapResult make_base_result(bool supported) {
            TrapResult result;
            result.available = true;
            result.supported = supported;
            return result;
        }

        TrapResult finalize_result(TrapResult result, const std::string &prefix) {
            std::ostringstream detail;
            detail << prefix;
            for (std::size_t index = 0; index < result.attempts.size(); ++index) {
                detail << "\nAttempt " << (index + 1) << ": " << result.attempts[index].detail;
            }
            result.detail = detail.str();
            return result;
        }

        // Only reached from the non-arm64 fallbacks, so the arm64-v8a build compiles no call to it.
        [[maybe_unused]] TrapResult build_unsupported_result(const std::string &detail) {
            TrapResult result;
            result.available = true;
            result.supported = false;
            result.detail = detail;
            return result;
        }

        // Read and set only from arm64-only code paths, so other ABIs compile no reference to it.
        [[maybe_unused]] bool g_sacrificialSyscallPackDisabled = false;

        std::string encode_basic_pack(
                bool available,
                bool supported,
                bool disabled,
                const std::string &detail
        ) {
            std::ostringstream output;
            output << "AVAILABLE=" << (available ? 1 : 0) << '\n';
            output << "SUPPORTED=" << (supported ? 1 : 0) << '\n';
            output << "DISABLED=" << (disabled ? 1 : 0) << '\n';
            output << "DETAIL=" << encode_value(detail) << '\n';
            return output.str();
        }

        // Used only from run_syscall_item, whose instantiations sit behind arm64-only guards.
        [[maybe_unused]] bool unsupported_syscall_errno(int err) {
            return err == ENOSYS || err == EINVAL;
        }

#if defined(__aarch64__)
        extern "C" unsigned long long virtualization_arm64_read_cntvct();
        extern "C" unsigned long long virtualization_arm64_read_cntfrq();
        extern "C" long virtualization_arm64_getpid_syscall();

        long asm_syscall6(
                long number,
                long arg0,
                long arg1,
                long arg2,
                long arg3,
                long arg4,
                long arg5,
                int *outErrno
        ) {
            register long x0 __asm__("x0") = arg0;
            register long x1 __asm__("x1") = arg1;
            register long x2 __asm__("x2") = arg2;
            register long x3 __asm__("x3") = arg3;
            register long x4 __asm__("x4") = arg4;
            register long x5 __asm__("x5") = arg5;
            register long x8 __asm__("x8") = number;
            __asm__ volatile("svc #0"
            : "+r"(x0)
            : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
            : "memory");
            if (x0 < 0) {
                if (outErrno != nullptr) {
                    *outErrno = static_cast<int>(-x0);
                }
                return -1;
            }
            if (outErrno != nullptr) {
                *outErrno = 0;
            }
            return x0;
        }

        /**
         * One syscall issued three times: twice through bionic's syscall() wrapper and once
         * through an inline svc.
         *
         * Only two mechanisms are present here, not three. The wrapper pair is deliberately
         * the same path twice, because that is what gives this attempt a noise floor to judge
         * the inline result against. Naming the second call "raw", as this struct once did,
         * implied a second independent layer and invited a comparison between a path and
         * itself.
         *
         * The comparison that carries meaning is wrapper against inline: userspace
         * interposition can reach the wrapper's PLT entry or its prologue, while an svc
         * compiled into this translation unit has no symbol to hook.
         */
        struct SyscallAttemptTriplet {
            long wrapperRet = -1;
            int wrapperErrno = 0;
            long wrapperRepeatRet = -1;
            int wrapperRepeatErrno = 0;
            long asmRet = -1;
            int asmErrno = 0;
            long long wrapperElapsedNs = 0;
            long long wrapperRepeatElapsedNs = 0;
            long long asmElapsedNs = 0;
        };

        // Applied to the gap between the inline call and the wrapper baseline, not to a raw
        // duration, so both keep their original role of admitting only a gross outlier.
        constexpr long long kTimingGapFactor = 4LL;
        constexpr long long kTimingGapFloorNs = 50000LL;

        /**
         * Whether two attempts at the same syscall agree on what happened.
         *
         * Return values are compared only for the failure case, where errno carries the
         * outcome. On success the number itself is not comparable: memfd_create and pidfd_open
         * hand back a freshly allocated descriptor, and which number the kernel picks depends
         * on what is free in the table at that moment. Requiring equality there would read an
         * ordinary descriptor-numbering difference as one layer disagreeing with another.
         */
        bool outcomes_agree(long firstRet, int firstErrno, long secondRet, int secondErrno) {
            const bool firstFailed = firstRet < 0;
            if (firstFailed != (secondRet < 0)) {
                return false;
            }
            return !firstFailed || firstErrno == secondErrno;
        }

        struct SyscallItemAccumulator {
            std::string label;
            int completedAttempts = 0;
            int suspiciousAttempts = 0;
            std::vector<TrapAttempt> attempts;
        };

        template <typename Callable>
        bool run_syscall_item(
                const std::string &label,
                Callable callable,
                SyscallItemAccumulator *accumulator
        ) {
            accumulator->label = label;
            for (int attempt = 0; attempt < 3; ++attempt) {
                SyscallAttemptTriplet triplet = callable(attempt);
                if (unsupported_syscall_errno(triplet.wrapperErrno) ||
                    unsupported_syscall_errno(triplet.wrapperRepeatErrno) ||
                    unsupported_syscall_errno(triplet.asmErrno)) {
                    return false;
                }

                // The wrapper pair is one path called twice, so a disagreement between them is
                // the call behaving non-reproducibly rather than a layer diverging. Without a
                // stable baseline there is nothing for the inline result to be compared
                // against, so the attempt records why and stays out of the completed tally.
                if (!outcomes_agree(triplet.wrapperRet, triplet.wrapperErrno,
                                    triplet.wrapperRepeatRet, triplet.wrapperRepeatErrno)) {
                    std::ostringstream unstable;
                    unstable << "wrapper pair disagreed (ret " << triplet.wrapperRet << "/"
                             << triplet.wrapperRepeatRet << ", errno " << triplet.wrapperErrno
                             << "/" << triplet.wrapperRepeatErrno
                             << "), no stable baseline to compare the inline svc against";
                    accumulator->attempts.push_back(TrapAttempt{false, unstable.str()});
                    continue;
                }

                const bool returnMismatch = !outcomes_agree(
                        triplet.wrapperRet, triplet.wrapperErrno,
                        triplet.asmRet, triplet.asmErrno
                );

                // Scaled against the wrapper pair's own gap rather than against the fastest of
                // the three. Those two calls take the same path, so whatever separates them is
                // this attempt's noise, mostly preemption; measuring the inline call against
                // the smallest raw sample instead let that noise alone clear the bar. The
                // factor and floor are the ones this trap already used, kept because they are
                // coarse on purpose: a syscall runs in single-digit microseconds, so the floor
                // means only a stall far outside that range counts.
                const long long controlGapNs = std::max(1LL, llabs(
                        triplet.wrapperElapsedNs - triplet.wrapperRepeatElapsedNs
                ));
                const long long wrapperFloorNs = std::min(
                        triplet.wrapperElapsedNs, triplet.wrapperRepeatElapsedNs
                );
                const long long asmGapNs = llabs(triplet.asmElapsedNs - wrapperFloorNs);
                const bool timingMismatch = asmGapNs > controlGapNs * kTimingGapFactor &&
                                            asmGapNs > kTimingGapFloorNs;

                const bool suspicious = returnMismatch || timingMismatch;
                accumulator->completedAttempts += 1;
                if (suspicious) {
                    accumulator->suspiciousAttempts += 1;
                }

                std::ostringstream detail;
                detail << "wrapper_ret=" << triplet.wrapperRet
                       << " wrapper_errno=" << triplet.wrapperErrno
                       << " wrapper_repeat_ret=" << triplet.wrapperRepeatRet
                       << " wrapper_repeat_errno=" << triplet.wrapperRepeatErrno
                       << " asm_ret=" << triplet.asmRet << " asm_errno=" << triplet.asmErrno
                       << " wrapper_ns=" << triplet.wrapperElapsedNs
                       << " wrapper_repeat_ns=" << triplet.wrapperRepeatElapsedNs
                       << " asm_ns=" << triplet.asmElapsedNs
                       << " control_gap_ns=" << controlGapNs
                       << " asm_gap_ns=" << asmGapNs;
                accumulator->attempts.push_back(TrapAttempt{suspicious, detail.str()});
            }
            return true;
        }

        std::string encode_sacrificial_item(const SyscallItemAccumulator &item) {
            std::ostringstream output;
            output << "ITEM=" << item.label << '\t' << 1 << '\t'
                   << item.completedAttempts << '\t'
                   << item.suspiciousAttempts << '\t'
                   << encode_value(item.attempts.empty() ? "" : item.attempts.front().detail) << '\n';
            for (const auto &attempt: item.attempts) {
                output << "ATTEMPT=" << item.label << '\t'
                       << (attempt.suspicious ? 1 : 0)
                       << '\t' << encode_value(attempt.detail) << '\n';
            }
            return output.str();
        }
#endif

    }  // namespace

    /**
     * Looks for sched_yield timings that repeat more evenly than real scheduling tends to.
     *
     * The bounds below are empirical, and sched_yield gives no specification to anchor them
     * to. Its man page puts the call's behaviour under SCHED_OTHER, which is what an Android
     * app thread runs, explicitly outside what is specified: "Use of sched_yield() with
     * nondeterministic scheduling policies such as SCHED_OTHER is unspecified".
     *
     * That same page also names the main false positive. "If the calling thread is the only
     * thread in the highest priority list at that time, it will continue to run after a call
     * to sched_yield()", so on an idle device no context switch happens and what is left to
     * measure is a bare syscall round trip, which repeats closely by nature. Evenness here is
     * therefore not by itself evidence of an emulated scheduler, which is why the bounds are
     * set tight enough that ordinary vDSO clock jitter clears them, and why two of three
     * attempts must agree before the consumer treats this as a signal at all.
     */
    TrapResult run_timing_trap() {
        // Tight enough that the jitter of the two clock reads around sched_yield normally
        // exceeds it on its own. Loosening it would start flagging idle devices.
        constexpr double kUniformityCeiling = 0.03;

        // Guards against reading a descheduled sample window as a tidy one. A yield costing
        // this long means the thread lost the CPU, so uniformity says nothing about the
        // scheduler's own behaviour.
        constexpr long long kMeanCeilingNs = 250000LL;

        // Microsecond granularity, so sub-microsecond yields all land in one bucket and this
        // does little work beyond rejecting obviously spread-out sample sets.
        constexpr std::size_t kBucketCeiling = 2;

        TrapResult result = make_base_result(true);
        for (int attempt = 0; attempt < 3; ++attempt) {
            std::vector<long long> samples;
            samples.reserve(32);
            for (int sample = 0; sample < 32; ++sample) {
                const long long start = monotonic_ns();
                sched_yield();
                const long long end = monotonic_ns();
                samples.push_back(end - start);
            }
            std::set<long long> buckets;
            for (const auto sample: samples) {
                buckets.insert(sample / 1000LL);
            }
            const std::optional<double> cv = coefficient_of_variation(samples);
            const long long mean = std::accumulate(samples.begin(), samples.end(), 0LL) /
                                   static_cast<long long>(samples.size());

            // Every sample reading as no elapsed time leaves no spread to judge, which
            // happens where the clock is too coarse to resolve a yield. Counting the attempt
            // would turn a measurement that did not happen into the most uniform result the
            // scale can express, so it stays out of the completed tally and the consumer's
            // two-attempt minimum keeps it off both verdicts.
            if (!cv.has_value()) {
                result.attempts.push_back(
                        TrapAttempt{false,
                                    "mean=0ns (no elapsed time resolved, uniformity "
                                    "unavailable)"}
                );
                continue;
            }

            const bool suspicious = buckets.size() <= kBucketCeiling &&
                                    *cv < kUniformityCeiling &&
                                    mean < kMeanCeilingNs;
            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }
            std::ostringstream detail;
            detail << "mean=" << mean << "ns cv=" << *cv
                   << " unique_us_buckets=" << buckets.size();
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(
                result,
                "Measures sched_yield timing evenness across three native attempts. "
                "sched_yield is unspecified under SCHED_OTHER and returns without switching "
                "when nothing else is runnable, so evenness alone is weak evidence."
        );
    }

    TrapResult run_syscall_parity_trap() {
        TrapResult result = make_base_result(true);
        const pid_t pid = getpid();
        for (int attempt = 0; attempt < 3; ++attempt) {
            std::ostringstream path;
            path << "/proc/self/definitely_missing_virtualization_" << pid << "_" << attempt;

            // Unlike the sacrificial pack, these two names are accurate: open() is a real
            // bionic entry point, and the second call goes straight to openat through
            // syscall(), so a hook on the former is observable against the latter.
            errno = 0;
            const long long libcStart = monotonic_ns();
            const int libcRet = open(path.str().c_str(), O_RDONLY | O_CLOEXEC);
            const int libcErrno = errno;
            if (libcRet >= 0) {
                close(libcRet);
            }
            const long long libcElapsed = monotonic_ns() - libcStart;

            errno = 0;
            const long long rawStart = monotonic_ns();
            const long rawRet = syscall(__NR_openat, AT_FDCWD, path.str().c_str(),
                                        O_RDONLY | O_CLOEXEC, 0);
            const int rawErrno = errno;
            if (rawRet >= 0) {
                close(static_cast<int>(rawRet));
            }
            const long long rawElapsed = monotonic_ns() - rawStart;

            const bool suspicious = libcRet != rawRet || libcErrno != rawErrno;
            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }

            std::ostringstream detail;
            detail << "libc_ret=" << libcRet << " libc_errno=" << libcErrno
                   << " raw_ret=" << rawRet << " raw_errno=" << rawErrno
                   << " libc_ns=" << libcElapsed << " raw_ns=" << rawElapsed;
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(result,
                               "Compares libc and raw openat error paths for a transient missing-path trap.");
    }

    /**
     * Checks the firmware-provided counter frequency against the rate the kernel's own
     * timekeeping runs at.
     *
     * This is not a comparison of two independent clocks, and must not be read as one. On
     * arm64 CLOCK_MONOTONIC comes from the same register this probe reads: the vDSO's
     * __arch_get_hw_counter (arch/arm64/include/asm/vdso/gettimeofday.h) issues
     * "isb; mrs cntvct_el0", or CNTVCTSS_EL0 where FEAT_ECV is present. Both sides of the
     * comparison therefore observe one counter, and what differs is the scaling: this probe
     * divides by CNTFRQ_EL0, while CLOCK_MONOTONIC applies the mult/shift the kernel derived
     * from the arch timer rate it established at boot.
     *
     * That makes the check worth running even so, because CNTFRQ_EL0 is not authoritative
     * about the hardware. Arm ARM D12.1.2 has it UNKNOWN at reset and written by firmware at
     * the highest exception level; nothing in hardware validates it. An environment that
     * advertises a frequency the counter does not actually tick at will disagree with the
     * kernel's calibrated rate, which is the divergence being looked for.
     */
    TrapResult run_asm_counter_trap() {
#if defined(__aarch64__)
        // CNTFRQ_EL0 carries the frequency in its ClockFreq field, bits [31:0]. Masking
        // bounds a firmware-written value before it is used as a divisor, so that upper bits
        // cannot pass the zero check below and then divide the counter delta down to nothing.
        constexpr unsigned long long kClockFreqMask = 0xffff'ffffULL;

        // Deliberately coarse: both sides read one counter, so they agree to within
        // clocksource rounding plus the two extra register reads inside the wall-clock
        // window. Only a gross mismatch, such as an advertised frequency several times off
        // the real tick rate, clears this. The cost of that margin is a false negative for
        // subtle timer scaling, which this trap cannot see.
        constexpr long long kGrossMismatchNumerator = 3LL;
        constexpr long long kGrossMismatchDenominator = 4LL;

        TrapResult result = make_base_result(true);
        for (int attempt = 0; attempt < 3; ++attempt) {
            const unsigned long long freq =
                    virtualization_arm64_read_cntfrq() & kClockFreqMask;
            const long long wallStart = monotonic_ns();
            const unsigned long long counterStart = virtualization_arm64_read_cntvct();
            for (int i = 0; i < 256; ++i) {
                syscall(__NR_getpid);
            }
            const unsigned long long counterEnd = virtualization_arm64_read_cntvct();
            const long long wallEnd = monotonic_ns();

            // A frequency of zero means firmware never programmed the register, so there is
            // no divisor and no measurement. Leaving the attempt uncounted keeps that apart
            // from a completed comparison that disagreed: the consumer needs two completed
            // attempts before it will call this either suspicious or clean, so an
            // unprogrammed register lands on neither instead of being reported as evidence.
            if (freq == 0ULL) {
                result.attempts.push_back(
                        TrapAttempt{false,
                                    "freq=0 (cntfrq_el0 unprogrammed, comparison unavailable)"}
                );
                continue;
            }

            // Zero covers both a counter that did not advance and one that went backwards.
            // Either is anomalous on its own: at the frequencies the architecture allows,
            // 256 syscalls always span several ticks.
            const unsigned long long counterDelta = counterEnd > counterStart
                                                    ? (counterEnd - counterStart)
                                                    : 0ULL;
            const long long wallDelta = wallEnd - wallStart;

            // Whole seconds are converted apart from the remainder so that counterDelta
            // never multiplies into an overflow. A straight counterDelta * 1e9 wraps once the
            // delta passes ~1.8e10 ticks, which is only ~18 seconds of counter at the 1GHz
            // fixed frequency Armv8.6 mandates, and this window can stretch that far if the
            // process is descheduled mid-loop. The remainder stays below freq, itself bounded
            // to 32 bits above, so its multiplication is in range.
            const unsigned long long deltaSeconds = counterDelta / freq;
            const unsigned long long deltaRemainder = counterDelta % freq;
            const long long counterNs = static_cast<long long>(
                    deltaSeconds * 1000000000ULL + (deltaRemainder * 1000000000ULL) / freq
            );
            const long long diff = llabs(counterNs - wallDelta);
            const bool suspicious = counterDelta == 0ULL ||
                                    (wallDelta > 0LL &&
                                     diff > (wallDelta * kGrossMismatchNumerator /
                                             kGrossMismatchDenominator));

            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }

            std::ostringstream detail;
            detail << "freq=" << freq << " counter_delta=" << counterDelta
                   << " counter_ns=" << counterNs << " wall_ns=" << wallDelta;
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(
                result,
                "Checks the firmware cntfrq_el0 value against the rate the kernel's own "
                "timekeeping uses. Both sides read cntvct_el0, so this is one counter scaled "
                "two ways, not two independent clocks."
        );
#else
        return build_unsupported_result("ASM counter trap is only supported on arm64-v8a.");
#endif
    }

    TrapResult run_asm_raw_syscall_trap() {
#if defined(__aarch64__)
        TrapResult result = make_base_result(true);
        for (int attempt = 0; attempt < 3; ++attempt) {
            const pid_t libcPid = getpid();
            const long rawPid = virtualization_arm64_getpid_syscall();
            const bool suspicious = rawPid <= 0 || static_cast<pid_t>(rawPid) != libcPid;
            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }
            std::ostringstream detail;
            detail << "libc_getpid=" << libcPid << " asm_getpid=" << rawPid;
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(result, "Compares libc getpid against an arm64 raw-svc syscall path.");
#else
        return build_unsupported_result("ASM raw syscall trap is only supported on arm64-v8a.");
#endif
    }

    std::string run_sacrificial_syscall_pack() {
#if defined(__aarch64__)
        if (g_sacrificialSyscallPackDisabled) {
            return encode_basic_pack(
                    true,
                    false,
                    true,
                    "Sacrificial syscall pack was disabled after a previous SIGSYS in this helper process."
            );
        }

        int pipefd[2] = {-1, -1};
        if (pipe(pipefd) != 0) {
            return encode_basic_pack(true, false, false, "Failed to create pipe for sacrificial syscall pack.");
        }

        const pid_t child = fork();
        if (child < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            return encode_basic_pack(true, false, false, "Failed to fork sacrificial syscall child.");
        }

        if (child == 0) {
            close(pipefd[0]);

            auto call_via_syscall = [](long number,
                                       long arg0,
                                       long arg1,
                                       long arg2,
                                       long arg3,
                                       long arg4,
                                       long arg5,
                                       int *outErrno) -> long {
                errno = 0;
                const long ret = syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
                if (outErrno != nullptr) {
                    *outErrno = errno;
                }
                return ret;
            };

            std::vector<SyscallItemAccumulator> items;
            items.reserve(5);

            SyscallItemAccumulator openat2Item;
            const bool openat2Supported = run_syscall_item("openat2", [&](int attempt) {
                const std::string path = "/proc/self/virtualization_openat2_missing_" + std::to_string(attempt);
                struct open_how how{};
                how.flags = static_cast<std::uint64_t>(O_RDONLY | O_CLOEXEC);
                SyscallAttemptTriplet triplet;
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_openat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        reinterpret_cast<long>(&how),
                        sizeof(how),
                        0,
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_openat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        reinterpret_cast<long>(&how),
                        sizeof(how),
                        0,
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_openat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        reinterpret_cast<long>(&how),
                        sizeof(how),
                        0,
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                return triplet;
            }, &openat2Item);

            SyscallItemAccumulator statxItem;
            const bool statxSupported = run_syscall_item("statx", [&](int attempt) {
                const std::string path = "/proc/self/virtualization_statx_missing_" + std::to_string(attempt);
                struct statx statxBuffer{};
                SyscallAttemptTriplet triplet;
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_statx,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        0,
                        STATX_BASIC_STATS,
                        reinterpret_cast<long>(&statxBuffer),
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_statx,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        0,
                        STATX_BASIC_STATS,
                        reinterpret_cast<long>(&statxBuffer),
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_statx,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        0,
                        STATX_BASIC_STATS,
                        reinterpret_cast<long>(&statxBuffer),
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                return triplet;
            }, &statxItem);

            SyscallItemAccumulator memfdItem;
            const bool memfdSupported = run_syscall_item("memfd_create", [&](int attempt) {
                const std::string name = "virt_memfd_" + std::to_string(attempt);
                SyscallAttemptTriplet triplet;
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_memfd_create,
                        reinterpret_cast<long>(name.c_str()),
                        MFD_CLOEXEC,
                        0,
                        0,
                        0,
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                if (triplet.wrapperRet >= 0) close(static_cast<int>(triplet.wrapperRet));
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_memfd_create,
                        reinterpret_cast<long>(name.c_str()),
                        MFD_CLOEXEC,
                        0,
                        0,
                        0,
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                if (triplet.wrapperRepeatRet >= 0) close(static_cast<int>(triplet.wrapperRepeatRet));
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_memfd_create,
                        reinterpret_cast<long>(name.c_str()),
                        MFD_CLOEXEC,
                        0,
                        0,
                        0,
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                if (triplet.asmRet >= 0) close(static_cast<int>(triplet.asmRet));
                return triplet;
            }, &memfdItem);

            SyscallItemAccumulator pidfdItem;
            const bool pidfdSupported = run_syscall_item("pidfd_open", [&](int) {
                SyscallAttemptTriplet triplet;
                const pid_t pid = getpid();
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_pidfd_open,
                        pid,
                        0,
                        0,
                        0,
                        0,
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                if (triplet.wrapperRet >= 0) close(static_cast<int>(triplet.wrapperRet));
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_pidfd_open,
                        pid,
                        0,
                        0,
                        0,
                        0,
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                if (triplet.wrapperRepeatRet >= 0) close(static_cast<int>(triplet.wrapperRepeatRet));
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_pidfd_open,
                        pid,
                        0,
                        0,
                        0,
                        0,
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                if (triplet.asmRet >= 0) close(static_cast<int>(triplet.asmRet));
                return triplet;
            }, &pidfdItem);

            SyscallItemAccumulator renameat2Item;
            const bool renameat2Supported = run_syscall_item("renameat2", [&](int attempt) {
                const std::string oldPath = "/proc/self/virtualization_renameat2_old_" + std::to_string(attempt);
                const std::string newPath = "/proc/self/virtualization_renameat2_new_" + std::to_string(attempt);
                SyscallAttemptTriplet triplet;
                const long long wrapperStart = monotonic_ns();
                triplet.wrapperRet = call_via_syscall(
                        __NR_renameat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(oldPath.c_str()),
                        AT_FDCWD,
                        reinterpret_cast<long>(newPath.c_str()),
                        0,
                        0,
                        &triplet.wrapperErrno
                );
                triplet.wrapperElapsedNs = monotonic_ns() - wrapperStart;
                const long long wrapperRepeatStart = monotonic_ns();
                triplet.wrapperRepeatRet = call_via_syscall(
                        __NR_renameat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(oldPath.c_str()),
                        AT_FDCWD,
                        reinterpret_cast<long>(newPath.c_str()),
                        0,
                        0,
                        &triplet.wrapperRepeatErrno
                );
                triplet.wrapperRepeatElapsedNs = monotonic_ns() - wrapperRepeatStart;
                const long long asmStart = monotonic_ns();
                triplet.asmRet = asm_syscall6(
                        __NR_renameat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(oldPath.c_str()),
                        AT_FDCWD,
                        reinterpret_cast<long>(newPath.c_str()),
                        0,
                        0,
                        &triplet.asmErrno
                );
                triplet.asmElapsedNs = monotonic_ns() - asmStart;
                return triplet;
            }, &renameat2Item);

            if (!(openat2Supported && statxSupported && memfdSupported && pidfdSupported && renameat2Supported)) {
                const std::string payload = encode_basic_pack(
                        true,
                        false,
                        false,
                        "Sacrificial syscall pack is unsupported on this kernel, ABI, or libc surface."
                );
                write(pipefd[1], payload.data(), payload.size());
                close(pipefd[1]);
                _exit(0);
            }

            items.push_back(openat2Item);
            items.push_back(statxItem);
            items.push_back(memfdItem);
            items.push_back(pidfdItem);
            items.push_back(renameat2Item);

            std::ostringstream payload;
            payload << "AVAILABLE=1\nSUPPORTED=1\nDISABLED=0\nDETAIL="
                    << encode_value("Executed the syscall pack in a sacrificial child process.") << '\n';
            for (const auto &item: items) {
                payload << encode_sacrificial_item(item);
            }
            const std::string serialized = payload.str();
            write(pipefd[1], serialized.data(), serialized.size());
            close(pipefd[1]);
            _exit(0);
        }

        close(pipefd[1]);
        int status = 0;
        waitpid(child, &status, 0);
        std::string payload;
        char buffer[1024];
        ssize_t read = 0;
        while ((read = ::read(pipefd[0], buffer, sizeof(buffer))) > 0) {
            payload.append(buffer, static_cast<std::size_t>(read));
        }
        close(pipefd[0]);

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
            g_sacrificialSyscallPackDisabled = true;
            return encode_basic_pack(
                    true,
                    false,
                    true,
                    "Sacrificial syscall child died with SIGSYS. The helper process will not run this pack again."
            );
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || payload.empty()) {
            return encode_basic_pack(
                    true,
                    false,
                    false,
                    "Sacrificial syscall child did not return a valid result."
            );
        }
        return payload;
#else
        return encode_basic_pack(
                true,
                false,
                false,
                "Sacrificial syscall pack is only supported on arm64-v8a."
        );
#endif
    }

    std::string encode_trap(const TrapResult &result) {
        std::ostringstream output;
        output << "AVAILABLE=" << (result.available ? 1 : 0) << '\n';
        output << "SUPPORTED=" << (result.supported ? 1 : 0) << '\n';
        output << "COMPLETED_ATTEMPTS=" << result.completedAttempts << '\n';
        output << "SUSPICIOUS_ATTEMPTS=" << result.suspiciousAttempts << '\n';
        output << "DETAIL=" << encode_value(result.detail) << '\n';
        for (const auto &attempt: result.attempts) {
            output << "ATTEMPT=" << (attempt.suspicious ? 1 : 0) << '\t'
                   << encode_value(attempt.detail) << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::virtualization
