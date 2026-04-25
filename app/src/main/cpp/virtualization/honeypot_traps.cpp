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
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace duckdetector::virtualization {

    namespace {

        std::string encode_value(const std::string &value) {
            std::string encoded = value;
            std::size_t pos = 0;
            while ((pos = encoded.find('\n', pos)) != std::string::npos) {
                encoded.replace(pos, 1, "\\n");
                pos += 2;
            }
            pos = 0;
            while ((pos = encoded.find('\r', pos)) != std::string::npos) {
                encoded.replace(pos, 1, "\\r");
                pos += 2;
            }
            return encoded;
        }

        long long monotonic_ns() {
            struct timespec now{};
            clock_gettime(CLOCK_MONOTONIC, &now);
            return static_cast<long long>(now.tv_sec) * 1000000000LL + now.tv_nsec;
        }

        double coefficient_of_variation(const std::vector<long long> &samples) {
            if (samples.empty()) {
                return 0.0;
            }
            const double mean = std::accumulate(samples.begin(), samples.end(), 0.0) /
                                static_cast<double>(samples.size());
            if (mean <= 0.0) {
                return 0.0;
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

        TrapResult build_unsupported_result(const std::string &detail) {
            TrapResult result;
            result.available = true;
            result.supported = false;
            result.detail = detail;
            return result;
        }

        bool g_sacrificialSyscallPackDisabled = false;

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

        bool unsupported_syscall_errno(int err) {
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

        struct SyscallAttemptTriplet {
            long libcRet = -1;
            int libcErrno = 0;
            long rawRet = -1;
            int rawErrno = 0;
            long asmRet = -1;
            int asmErrno = 0;
            long long libcElapsedNs = 0;
            long long rawElapsedNs = 0;
            long long asmElapsedNs = 0;
        };

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
                if (unsupported_syscall_errno(triplet.libcErrno) ||
                    unsupported_syscall_errno(triplet.rawErrno) ||
                    unsupported_syscall_errno(triplet.asmErrno)) {
                    return false;
                }

                const bool returnMismatch = triplet.libcRet != triplet.rawRet ||
                                            triplet.libcRet != triplet.asmRet ||
                                            triplet.libcErrno != triplet.rawErrno ||
                                            triplet.libcErrno != triplet.asmErrno;
                const long long fastest = std::max(1LL, std::min(
                        triplet.libcElapsedNs,
                        std::min(triplet.rawElapsedNs, triplet.asmElapsedNs)
                ));
                const long long slowest = std::max(
                        triplet.libcElapsedNs,
                        std::max(triplet.rawElapsedNs, triplet.asmElapsedNs)
                );
                const bool timingMismatch = slowest > fastest * 4LL && slowest - fastest > 50000LL;
                const bool suspicious = returnMismatch || timingMismatch;
                accumulator->completedAttempts += 1;
                if (suspicious) {
                    accumulator->suspiciousAttempts += 1;
                }

                std::ostringstream detail;
                detail << "libc_ret=" << triplet.libcRet << " libc_errno=" << triplet.libcErrno
                       << " raw_ret=" << triplet.rawRet << " raw_errno=" << triplet.rawErrno
                       << " asm_ret=" << triplet.asmRet << " asm_errno=" << triplet.asmErrno
                       << " libc_ns=" << triplet.libcElapsedNs
                       << " raw_ns=" << triplet.rawElapsedNs
                       << " asm_ns=" << triplet.asmElapsedNs;
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

    TrapResult run_timing_trap() {
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
            const double cv = coefficient_of_variation(samples);
            const long long mean = std::accumulate(samples.begin(), samples.end(), 0LL) /
                                   static_cast<long long>(samples.size());
            const bool suspicious = buckets.size() <= 2 && cv < 0.03 && mean < 250000LL;
            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }
            std::ostringstream detail;
            detail << "mean=" << mean << "ns cv=" << cv << " unique_us_buckets=" << buckets.size();
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(result, "Measures scheduling jitter across three native attempts.");
    }

    TrapResult run_syscall_parity_trap() {
        TrapResult result = make_base_result(true);
        const pid_t pid = getpid();
        for (int attempt = 0; attempt < 3; ++attempt) {
            std::ostringstream path;
            path << "/proc/self/definitely_missing_virtualization_" << pid << "_" << attempt;

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

    TrapResult run_asm_counter_trap() {
#if defined(__aarch64__)
        TrapResult result = make_base_result(true);
        for (int attempt = 0; attempt < 3; ++attempt) {
            const unsigned long long freq = virtualization_arm64_read_cntfrq();
            const long long wallStart = monotonic_ns();
            const unsigned long long counterStart = virtualization_arm64_read_cntvct();
            for (int i = 0; i < 256; ++i) {
                syscall(__NR_getpid);
            }
            const unsigned long long counterEnd = virtualization_arm64_read_cntvct();
            const long long wallEnd = monotonic_ns();

            const unsigned long long counterDelta = counterEnd > counterStart
                                                    ? (counterEnd - counterStart)
                                                    : 0ULL;
            const long long wallDelta = wallEnd - wallStart;
            const long long counterNs = (freq > 0ULL)
                                        ? static_cast<long long>((counterDelta * 1000000000ULL) / freq)
                                        : 0LL;
            const long long diff = llabs(counterNs - wallDelta);
            const bool suspicious = freq == 0ULL || counterDelta == 0ULL ||
                                    (wallDelta > 0LL && diff > (wallDelta * 3LL / 4LL));

            result.completedAttempts += 1;
            if (suspicious) {
                result.suspiciousAttempts += 1;
            }

            std::ostringstream detail;
            detail << "freq=" << freq << " counter_delta=" << counterDelta
                   << " counter_ns=" << counterNs << " wall_ns=" << wallDelta;
            result.attempts.push_back(TrapAttempt{suspicious, detail.str()});
        }
        return finalize_result(result, "Correlates arm64 cntvct or cntfrq readings with wall-clock work windows.");
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
                const long long libcStart = monotonic_ns();
                triplet.libcRet = call_via_syscall(
                        __NR_openat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        reinterpret_cast<long>(&how),
                        sizeof(how),
                        0,
                        0,
                        &triplet.libcErrno
                );
                triplet.libcElapsedNs = monotonic_ns() - libcStart;
                const long long rawStart = monotonic_ns();
                triplet.rawRet = call_via_syscall(
                        __NR_openat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        reinterpret_cast<long>(&how),
                        sizeof(how),
                        0,
                        0,
                        &triplet.rawErrno
                );
                triplet.rawElapsedNs = monotonic_ns() - rawStart;
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
                const long long libcStart = monotonic_ns();
                triplet.libcRet = call_via_syscall(
                        __NR_statx,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        0,
                        STATX_BASIC_STATS,
                        reinterpret_cast<long>(&statxBuffer),
                        0,
                        &triplet.libcErrno
                );
                triplet.libcElapsedNs = monotonic_ns() - libcStart;
                const long long rawStart = monotonic_ns();
                triplet.rawRet = call_via_syscall(
                        __NR_statx,
                        AT_FDCWD,
                        reinterpret_cast<long>(path.c_str()),
                        0,
                        STATX_BASIC_STATS,
                        reinterpret_cast<long>(&statxBuffer),
                        0,
                        &triplet.rawErrno
                );
                triplet.rawElapsedNs = monotonic_ns() - rawStart;
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
                const long long libcStart = monotonic_ns();
                triplet.libcRet = call_via_syscall(
                        __NR_memfd_create,
                        reinterpret_cast<long>(name.c_str()),
                        MFD_CLOEXEC,
                        0,
                        0,
                        0,
                        0,
                        &triplet.libcErrno
                );
                triplet.libcElapsedNs = monotonic_ns() - libcStart;
                if (triplet.libcRet >= 0) close(static_cast<int>(triplet.libcRet));
                const long long rawStart = monotonic_ns();
                triplet.rawRet = call_via_syscall(
                        __NR_memfd_create,
                        reinterpret_cast<long>(name.c_str()),
                        MFD_CLOEXEC,
                        0,
                        0,
                        0,
                        0,
                        &triplet.rawErrno
                );
                triplet.rawElapsedNs = monotonic_ns() - rawStart;
                if (triplet.rawRet >= 0) close(static_cast<int>(triplet.rawRet));
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
                const long long libcStart = monotonic_ns();
                triplet.libcRet = call_via_syscall(
                        __NR_pidfd_open,
                        pid,
                        0,
                        0,
                        0,
                        0,
                        0,
                        &triplet.libcErrno
                );
                triplet.libcElapsedNs = monotonic_ns() - libcStart;
                if (triplet.libcRet >= 0) close(static_cast<int>(triplet.libcRet));
                const long long rawStart = monotonic_ns();
                triplet.rawRet = call_via_syscall(
                        __NR_pidfd_open,
                        pid,
                        0,
                        0,
                        0,
                        0,
                        0,
                        &triplet.rawErrno
                );
                triplet.rawElapsedNs = monotonic_ns() - rawStart;
                if (triplet.rawRet >= 0) close(static_cast<int>(triplet.rawRet));
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
                const long long libcStart = monotonic_ns();
                triplet.libcRet = call_via_syscall(
                        __NR_renameat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(oldPath.c_str()),
                        AT_FDCWD,
                        reinterpret_cast<long>(newPath.c_str()),
                        0,
                        0,
                        &triplet.libcErrno
                );
                triplet.libcElapsedNs = monotonic_ns() - libcStart;
                const long long rawStart = monotonic_ns();
                triplet.rawRet = call_via_syscall(
                        __NR_renameat2,
                        AT_FDCWD,
                        reinterpret_cast<long>(oldPath.c_str()),
                        AT_FDCWD,
                        reinterpret_cast<long>(newPath.c_str()),
                        0,
                        0,
                        &triplet.rawErrno
                );
                triplet.rawElapsedNs = monotonic_ns() - rawStart;
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
