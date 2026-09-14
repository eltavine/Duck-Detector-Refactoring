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

#include "nativeroot/probes/kernelpatch_superkey_probe.h"

#include <csignal>
#include <cstdio>
#include <string>
#include <cstdint>

#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace duckdetector::nativeroot {

#if defined(__aarch64__)

    namespace {
        constexpr int kAttempts = 4;
        // KernelPatch reuses the arm64 truncate slot as its supercall entry.
        constexpr int kSupercallNr = 45;
        // The arm64 truncate entry takes a 64-bit length, and a negative value
        // is the only input the syscall body rejects before it ever derives a
        // user pointer from arg0.
        constexpr long kInvalidLength = -1;

        struct SuperkeyResult {
            std::uint8_t checked = 0;
            std::uint8_t hit = 0;
            std::uint8_t pre_resident = 0;
            std::uint8_t control_resident = 0;
            std::uint8_t mincore_failed = 0;
        };

        static inline void *map_fresh_page(const std::size_t page_size) {
            return mmap(
                    nullptr,
                    page_size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0
            );
        }

        static inline bool is_page_resident(
                void *address,
                const std::size_t length,
                bool &query_failed
        ) {
            unsigned char vec = 0;
            if (syscall(__NR_mincore, address, length, &vec) != 0) {
                query_failed = true;
                return false;
            }
            return (vec & 0x1U) != 0;
        }

        // KernelPatch's supercall handler reads arg0 to compare it against the
        // superkey, and it is the first reader: the read happens ahead of the
        // syscall body. That read faults the page in. A stock kernel rejects a
        // negative length in do_sys_truncate() before it derives a user
        // pointer, so arg0 stays untouched and the page keeps its empty PTE.
        // Nothing is dereferenced on the stock path, which makes this a state
        // check rather than a timing one.
        void measure_residency(SuperkeyResult &out_result) {
            const long page_size_long = sysconf(_SC_PAGESIZE);
            const std::size_t page_size = page_size_long > 0
                                          ? static_cast<std::size_t>(page_size_long)
                                          : 4096U;

            // Never handed to the syscall, so it has to stay non-resident. If
            // it does not, mincore is not reporting what this check assumes.
            void *control = map_fresh_page(page_size);
            const bool control_mapped = control != MAP_FAILED;

            for (int i = 0; i < kAttempts; i++) {
                void *page = map_fresh_page(page_size);
                if (page == MAP_FAILED) {
                    continue;
                }

                out_result.checked++;

                bool query_failed = false;
                if (is_page_resident(page, page_size, query_failed)) {
                    // A fresh anonymous mapping has no PTE yet, so a resident
                    // report here means the measurement cannot be trusted.
                    out_result.pre_resident++;
                    munmap(page, page_size);
                    continue;
                }
                if (query_failed) {
                    out_result.mincore_failed++;
                    munmap(page, page_size);
                    continue;
                }

                syscall(kSupercallNr, page, kInvalidLength);

                query_failed = false;
                if (is_page_resident(page, page_size, query_failed)) {
                    out_result.hit++;
                }
                if (query_failed) {
                    out_result.mincore_failed++;
                }

                munmap(page, page_size);
            }

            if (control_mapped) {
                bool query_failed = false;
                if (is_page_resident(control, page_size, query_failed)) {
                    out_result.control_resident = 1;
                }
                if (query_failed) {
                    out_result.mincore_failed++;
                }
                munmap(control, page_size);
            }
        }

        bool run_attempts_in_child(
                SuperkeyResult &out_result,
                bool &blocked_by_seccomp
        ) {
            int pipe_fds[2] = {-1, -1};
            if (pipe(pipe_fds) != 0) return false;

            fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC);
            fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

            const pid_t pid = fork();
            if (pid < 0) {
                close(pipe_fds[0]);
                close(pipe_fds[1]);
                return false;
            }

            if (pid == 0) {
                close(pipe_fds[0]);

                SuperkeyResult child_result{};
                measure_residency(child_result);

                const ssize_t ignored = write(pipe_fds[1], &child_result, sizeof(child_result));
                (void) ignored;
                close(pipe_fds[1]);
                _exit(0);
            }

            close(pipe_fds[1]);

            int status = 0;
            pid_t waited_pid;
            do {
                waited_pid = waitpid(pid, &status, 0);
            } while (waited_pid < 0 && errno == EINTR);
            if (waited_pid < 0) {
                close(pipe_fds[0]);
                return false;
            }

            if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
                blocked_by_seccomp = true;
                close(pipe_fds[0]);
                return false;
            }

            const ssize_t bytes_read = read(pipe_fds[0], &out_result, sizeof(out_result));
            close(pipe_fds[0]);

            return WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                   bytes_read == static_cast<ssize_t>(sizeof(out_result));
        }
    } // namespace

    ProbeResult run_kernelpatch_superkey_check() {
        ProbeResult result;
        bool blocked = false;
        SuperkeyResult residency{};

        if (!run_attempts_in_child(residency, blocked)) {
            if (blocked) {
                result.checked_count = 1;
                result.denied_count = 1;
                result.findings.push_back(
                    Finding{
                        .group = "SECCOMP",
                        .label = "System Call Filtered",
                        .value = "SIGSYS Received",
                        .detail = "Syscall 45 was blocked by Seccomp on ARM64.",
                        .severity = Severity::kDanger,
                    }
                );
            }
            return result;
        }

        result.checked_count = residency.checked;

        char detail[256];
        snprintf(
                detail,
                sizeof(detail),
                "Probed attempts: %u, page faulted in: %u, pre-resident: %u, control resident: %u, mincore errors: %u",
                static_cast<unsigned>(residency.checked),
                static_cast<unsigned>(residency.hit),
                static_cast<unsigned>(residency.pre_resident),
                static_cast<unsigned>(residency.control_resident),
                static_cast<unsigned>(residency.mincore_failed)
        );

        result.extra_text = detail;

        // Without a clean control the residency report could come from mincore
        // semantics instead of the syscall, so the run is reported as
        // unavailable rather than clean.
        if (residency.control_resident != 0 || residency.mincore_failed != 0) {
            return result;
        }

        if (residency.hit > 0) {
            result.flags.apatch = true;
            result.hit_count = residency.hit;

            result.findings.push_back(
                    Finding{
                            .group = "SYSCALL",
                            .label = "KernelPatch superkey read",
                            .value = "Detected",
                            .detail = detail,
                            .severity = Severity::kDanger,
                    }
            );
        }

        return result;
    }

#else

    ProbeResult run_kernelpatch_superkey_check() {
        ProbeResult result;
        result.extra_text = "";
        return result;
    }

#endif // aarch64

} // namespace duckdetector::nativeroot
