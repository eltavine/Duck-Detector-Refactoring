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

#ifndef DUCKDETECTOR_TEE_COMMON_SYSCALL_FACADE_H
#define DUCKDETECTOR_TEE_COMMON_SYSCALL_FACADE_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace ducktee::common {

    enum class SyscallBackend {
        Libc,
        Syscall,
        Asm,
    };

    struct SyscallCallResult {
        long value = -1;
        int error_number = 0;
        bool available = false;
    };

    enum class LocalTimerKind {
        Monotonic,
        Arm64Cntvct,
    };

    struct LocalTimerSelection {
        LocalTimerKind kind = LocalTimerKind::Monotonic;
        std::string source_label = "clock_monotonic";
        std::string fallback_reason;
        std::string affinity_status = "not_requested";
    };

    const char *backend_label(SyscallBackend backend);

    bool backend_available(SyscallBackend backend);

    SyscallCallResult invoke_syscall3(
            SyscallBackend backend,
            long number,
            long arg0,
            long arg1,
            long arg2
    );

    SyscallCallResult invoke_syscall6(
            SyscallBackend backend,
            long number,
            long arg0,
            long arg1,
            long arg2,
            long arg3,
            long arg4,
            long arg5
    );

    SyscallCallResult invoke_open_readonly(SyscallBackend backend, const char *path);

    SyscallCallResult invoke_ioctl(
            SyscallBackend backend,
            int fd,
            unsigned long request,
            void *arg
    );

    SyscallCallResult invoke_getpid(SyscallBackend backend);

    bool monotonic_time_ns(SyscallBackend backend, std::uint64_t *out_ns);

    bool register_timer_time_ns(std::uint64_t *out_ns);

    bool bind_current_thread_to_cpu0();

    bool select_preferred_local_timer(
            bool request_cpu0_affinity,
            LocalTimerSelection *out
    );

    bool local_timer_now_ns(const LocalTimerSelection &timer, std::uint64_t *out_ns);

    long raw_syscall3(long number, long arg0, long arg1, long arg2);

    int raw_open_readonly(const char *path);

    long raw_ioctl(int fd, unsigned long request, void *arg);

    bool bytes_equal(const void *lhs, const void *rhs, std::size_t length);

}  // namespace ducktee::common

#endif  // DUCKDETECTOR_TEE_COMMON_SYSCALL_FACADE_H
