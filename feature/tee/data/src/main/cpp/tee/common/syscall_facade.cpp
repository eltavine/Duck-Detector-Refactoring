/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

#include "tee/common/syscall_facade.h"

#include "common/arm64_counter.h"
#include "tee/common/local_timer.h"
#include "tee/common/local_timer_internal.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace ducktee::common {

    namespace {

#if defined(__aarch64__) || defined(__arm__) || defined(__i386__) || defined(__x86_64__)
        extern "C" long tee_asm_syscall6(
                long number,
                long arg0,
                long arg1,
                long arg2,
                long arg3,
                long arg4,
                long arg5
        );

        constexpr bool kAsmBackendCompiled = true;
#else
        constexpr bool kAsmBackendCompiled = false;
#endif

        SyscallCallResult make_unavailable_result() {
            return SyscallCallResult{
                    .value = -1,
                    .error_number = ENOSYS,
                    .available = false,
            };
        }

        SyscallCallResult from_errno_result(long value, int error_number) {
            return SyscallCallResult{
                    .value = value,
                    .error_number = (value == -1) ? error_number : 0,
                    .available = true,
            };
        }

        SyscallCallResult from_raw_kernel_result(long raw_value) {
            if (raw_value < 0 && raw_value >= -4095) {
                return SyscallCallResult{
                        .value = -1,
                        .error_number = static_cast<int>(-raw_value),
                        .available = true,
                };
            }
            return SyscallCallResult{
                    .value = raw_value,
                    .error_number = 0,
                    .available = true,
            };
        }

        bool read_monotonic_via_result(
                const SyscallCallResult &call,
                const timespec &ts,
                std::uint64_t *out_ns
        ) {
            if (!call.available || call.value != 0 || out_ns == nullptr) {
                return false;
            }
            *out_ns = static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
                      static_cast<std::uint64_t>(ts.tv_nsec);
            return true;
        }

        bool monotonic_now(std::uint64_t *out_ns) {
            return monotonic_time_ns(SyscallBackend::Libc, out_ns);
        }

#if defined(__aarch64__)
        bool arm64_cntvct_raw(std::uint64_t *out_counter) {
            if (out_counter == nullptr) {
                return false;
            }
            const auto counter = duckdetector::common::arm64_counter::read_ticks();
            if (counter == 0ULL) {
                return false;
            }
            *out_counter = counter;
            return true;
        }

        std::uint64_t arm64_effective_frequency_hz() {
            return duckdetector::common::arm64_counter::frequency_hz();
        }

        bool arm64_cntvct_now(std::uint64_t *out_ns) {
            return duckdetector::common::arm64_counter::read_time_ns(out_ns);
        }
#endif

    }  // namespace

#if defined(__aarch64__)
    namespace detail {

        bool arm64_cntvct_self_check(std::string *failure_reason) {
            const std::uint64_t frequency = arm64_effective_frequency_hz();
            if (frequency == 0ULL) {
                if (failure_reason != nullptr) {
                    *failure_reason = "cntfrq was zero";
                }
                return false;
            }

            // Selection must agree with use: the nanosecond conversion has its own range guard, so a
            // counter this probe cannot convert must not be chosen as the timer source.
            std::uint64_t convertible_ns = 0;
            if (!arm64_cntvct_now(&convertible_ns)) {
                if (failure_reason != nullptr) {
                    *failure_reason = "cntvct could not be converted to nanoseconds";
                }
                return false;
            }

            std::uint64_t previous = 0;
            if (!arm64_cntvct_raw(&previous)) {
                if (failure_reason != nullptr) {
                    *failure_reason = "cntvct read failed";
                }
                return false;
            }
            if (previous == 0ULL) {
                if (failure_reason != nullptr) {
                    *failure_reason = "cntvct was zero";
                }
                return false;
            }

            int same_count = 0;
            for (int index = 0; index < 64; ++index) {
                std::uint64_t current = 0;
                if (!arm64_cntvct_raw(&current)) {
                    if (failure_reason != nullptr) {
                        *failure_reason = "cntvct read failed during self-check";
                    }
                    return false;
                }
                if (current < previous) {
                    if (failure_reason != nullptr) {
                        *failure_reason = "cntvct regressed";
                    }
                    return false;
                }
                if (current == previous) {
                    ++same_count;
                }
                previous = current;
            }

            if (same_count >= 60) {
                if (failure_reason != nullptr) {
                    *failure_reason = "cntvct stayed flat too often";
                }
                return false;
            }
            return true;
        }

    }  // namespace detail
#endif

    const char *backend_label(SyscallBackend backend) {
        switch (backend) {
            case SyscallBackend::Libc:
                return "libc";
            case SyscallBackend::Syscall:
                return "syscall";
            case SyscallBackend::Asm:
                return "asm";
        }
        return "unknown";
    }

    bool backend_available(SyscallBackend backend) {
        return backend != SyscallBackend::Asm || kAsmBackendCompiled;
    }

    SyscallCallResult invoke_syscall6(
            SyscallBackend backend,
            long number,
            long arg0,
            long arg1,
            long arg2,
            long arg3,
            long arg4,
            long arg5
    ) {
        switch (backend) {
            case SyscallBackend::Libc:
                return make_unavailable_result();
            case SyscallBackend::Syscall: {
                errno = 0;
                const long value = syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
                return from_errno_result(value, errno);
            }
            case SyscallBackend::Asm:
                if (!kAsmBackendCompiled) {
                    return make_unavailable_result();
                }
                return from_raw_kernel_result(
                        tee_asm_syscall6(number, arg0, arg1, arg2, arg3, arg4, arg5)
                );
        }
        return make_unavailable_result();
    }

    SyscallCallResult invoke_syscall3(
            SyscallBackend backend,
            long number,
            long arg0,
            long arg1,
            long arg2
    ) {
        return invoke_syscall6(backend, number, arg0, arg1, arg2, 0, 0, 0);
    }

    SyscallCallResult invoke_ioctl(
            SyscallBackend backend,
            int fd,
            unsigned long request,
            void *arg
    ) {
        switch (backend) {
            case SyscallBackend::Libc: {
                errno = 0;
                const int value = ioctl(fd, request, arg);
                return from_errno_result(value, errno);
            }
            case SyscallBackend::Syscall:
            case SyscallBackend::Asm:
#if defined(__NR_ioctl)
                return invoke_syscall3(
                        backend,
                        __NR_ioctl,
                        fd,
                        static_cast<long>(request),
                        reinterpret_cast<long>(arg)
                );
#else
                return make_unavailable_result();
#endif
        }
        return make_unavailable_result();
    }

    SyscallCallResult invoke_getpid(SyscallBackend backend) {
        switch (backend) {
            case SyscallBackend::Libc:
                return SyscallCallResult{
                        .value = static_cast<long>(getpid()),
                        .error_number = 0,
                        .available = true,
                };
            case SyscallBackend::Syscall:
            case SyscallBackend::Asm:
#if defined(__NR_getpid)
                return invoke_syscall3(backend, __NR_getpid, 0, 0, 0);
#else
                return make_unavailable_result();
#endif
        }
        return make_unavailable_result();
    }

    bool monotonic_time_ns(SyscallBackend backend, std::uint64_t *out_ns) {
        timespec ts{};
        switch (backend) {
            case SyscallBackend::Libc: {
                errno = 0;
                const int value = clock_gettime(CLOCK_MONOTONIC, &ts);
                return read_monotonic_via_result(from_errno_result(value, errno), ts, out_ns);
            }
            case SyscallBackend::Syscall:
            case SyscallBackend::Asm:
#if defined(__NR_clock_gettime)
                return read_monotonic_via_result(
                        invoke_syscall3(
                                backend,
                                __NR_clock_gettime,
                                CLOCK_MONOTONIC,
                                reinterpret_cast<long>(&ts),
                                0
                        ),
                        ts,
                        out_ns
                );
#else
                return false;
#endif
        }
        return false;
    }

    bool register_timer_time_ns(std::uint64_t *out_ns) {
#if defined(__aarch64__)
        return arm64_cntvct_now(out_ns);
#else
        static_cast<void>(out_ns);
        return false;
#endif
    }

    bool local_timer_now_ns(const LocalTimerSelection &timer, std::uint64_t *out_ns) {
        switch (timer.kind) {
            case LocalTimerKind::Monotonic:
                return monotonic_now(out_ns);
            case LocalTimerKind::Arm64Cntvct:
#if defined(__aarch64__)
                return arm64_cntvct_now(out_ns);
#else
                return false;
#endif
        }
        return false;
    }

    bool bytes_equal(const void *lhs, const void *rhs, std::size_t length) {
        return std::memcmp(lhs, rhs, length) == 0;
    }

}  // namespace ducktee::common
