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

#include "nativeroot/probes/kernelpatch_nr_supercall_latency_probe.h"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <cstdint>

#include <fcntl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace duckdetector::nativeroot {

#if defined(__aarch64__)

    namespace {
        constexpr int kIterations = 100000;

        // KernelPatch reuses the arm64 truncate slot as its supercall entry: its
        // uapi/scdefs.h defines __NR_supercall as 45 next to the commented-out
        // __NR3264_truncate it replaces, and the hook is installed with
        // hook_syscalln(__NR_supercall, ...). The NDK confirms __NR_truncate is 45 on
        // aarch64, so on an unpatched kernel these calls reach truncate instead.
        constexpr int kSupercallNr = 45;

        // SUPERCALL_HELLO from the same header, and also the length an unpatched kernel
        // takes as the truncate target size.
        constexpr unsigned long kSupercallHello = 0x1000;

        // 128 bytes including the terminator, matching the "128 bytes key string" case in
        // the KernelPatch benchmark this probe is calibrated against. The length is the
        // signal: a vulnerable build copies the whole key before rejecting it, so shortening
        // this buffer would shrink the very difference being measured.
        constexpr int kKeyBufferSize = 128;

        // Separates the two populations measured in KernelPatch commit 84169d5d ("patch:
        // trying fix side channel attack"), which reports averages for the same two
        // argument shapes this probe uses:
        //
        //   vulnerable build   4.281 us vs 0.460 us -> diff 3.82 us
        //   fixed build        0.943 us vs 0.607 us -> diff 0.34 us
        //   no KernelPatch     0.792 us vs 0.446 us -> diff 0.35 us
        //
        // A clean kernel therefore does show a positive difference: both calls land in
        // truncate, and the 127-byte path costs a strncpy_from_user plus a path walk that
        // the empty path skips by failing immediately. That baseline is an order of
        // magnitude below the vulnerable case, and this constant sits between them.
        //
        // Scope, because the commit is what closed the leak: only builds older than
        // 84169d5d are visible here. That commit stopped copying the key before
        // authentication, which collapses the fixed build onto the clean baseline, so this
        // probe cannot distinguish a current KernelPatch from an unmodified kernel and a
        // difference below this constant is not evidence of a clean kernel. Detection of
        // current builds rests on run_kernelpatch_superkey_check instead.
        constexpr double kVulnerableDiffMicros = 3.0;

        /**
         * Fills a key buffer that an unpatched kernel cannot resolve to a real file.
         *
         * An unpatched kernel reads arg0 as a truncate path, so the buffer doubles as one.
         * It is kept absolute because a bare run of 'A' bytes is relative and would resolve
         * against the process working directory, where a file of that name would have been
         * truncated to kSupercallHello bytes. Nothing can create this name under /, so the
         * path walk fails before truncate reaches a write.
         */
        void fill_unresolvable_key(char (&buffer)[kKeyBufferSize]) {
            memset(buffer, 'A', kKeyBufferSize - 1);
            buffer[0] = '/';
            buffer[kKeyBufferSize - 1] = '\0';
        }

        static inline uint64_t get_cntfrq() {
            uint64_t val;
            asm volatile("mrs %0, cntfrq_el0" : "=r" (val));
            return val;
        }

        static inline uint64_t get_cntvct() {
            uint64_t val;
            asm volatile("isb; mrs %0, cntvct_el0; isb" : "=r" (val));
            return val;
        }

        /**
         * Pins the caller to the first CPU it is already allowed on, so that both variants
         * are timed on one core rather than wherever the scheduler places each of them.
         */
        bool bind_to_single_cpu() {
            cpu_set_t affinity;
            CPU_ZERO(&affinity);
            if (sched_getaffinity(0, sizeof(affinity), &affinity) != 0) {
                return false;
            }
            for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
                if (!CPU_ISSET(cpu, &affinity)) {
                    continue;
                }
                cpu_set_t single;
                CPU_ZERO(&single);
                CPU_SET(cpu, &single);
                return sched_setaffinity(0, sizeof(single), &single) == 0;
            }
            return false;
        }

        inline uint64_t time_one_call(const char *buffer) {
            const uint64_t start = get_cntvct();
            syscall(kSupercallNr, buffer, kSupercallHello);
            return get_cntvct() - start;
        }

        /**
         * Times both argument shapes interleaved on the same core.
         *
         * Interleaving matters because the two means are compared against each other. Run
         * back to back, any frequency or thermal drift over the measurement window landed
         * entirely on whichever variant ran second and showed up as a difference between
         * them. Alternating spreads that drift across both.
         */
        bool measure_latencies(const char *full, const char *empty, double *out_full_us,
                               double *out_empty_us) {
            const uint64_t freq = get_cntfrq() & 0xffff'ffffULL;
            if (freq == 0) {
                return false;
            }

            // Warm up both paths so neither mean carries first-call cost.
            time_one_call(full);
            time_one_call(empty);

            uint64_t full_ticks = 0;
            uint64_t empty_ticks = 0;
            for (int i = 0; i < kIterations; i++) {
                full_ticks += time_one_call(full);
                empty_ticks += time_one_call(empty);
            }

            const double scale = static_cast<double>(freq) * kIterations;
            *out_full_us = (static_cast<double>(full_ticks) * 1000000.0) / scale;
            *out_empty_us = (static_cast<double>(empty_ticks) * 1000000.0) / scale;
            return true;
        }

        struct LatencyResult {
            double full_latency;
            double empty_latency;
            bool success;
            bool pinned;
        };

        bool run_benchmark_in_child(LatencyResult &out_result, bool &blocked_by_seccomp) {
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

                char key[kKeyBufferSize];
                fill_unresolvable_key(key);

                LatencyResult result{};
                result.pinned = bind_to_single_cpu();
                result.success = measure_latencies(
                        key,
                        "",
                        &result.full_latency,
                        &result.empty_latency
                );

                const ssize_t ignored = write(pipe_fds[1], &result, sizeof(result));
                (void) ignored;
                close(pipe_fds[1]);
                _exit(0);
            }

            close(pipe_fds[1]);
            int status = 0;
            if (waitpid(pid, &status, 0) < 0) {
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

    ProbeResult run_kernelpatch_supercall_latency_check() {
        ProbeResult result;
        bool blocked = false;
        LatencyResult latencies{};

        if (!run_benchmark_in_child(latencies, blocked)) {
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

        result.checked_count = 1;
        if (!latencies.success) return result;

        const double diff = latencies.full_latency - latencies.empty_latency;

        char detail[256];
        snprintf(
                detail,
                sizeof(detail),
                "Key path: %.4f us, empty key: %.4f us, diff: %.4f us, same-core: %s",
                latencies.full_latency,
                latencies.empty_latency,
                diff,
                latencies.pinned ? "yes" : "no"
        );

        result.extra_text = detail;

        if (diff > kVulnerableDiffMicros) {
            result.flags.apatch = true;
            result.hit_count = 1;

            result.findings.push_back(
                    Finding{
                            .group = "SYSCALL",
                            .label = "KernelPatch supercall key-length delay",
                            .value = "Detected (pre-84169d5d build)",
                            .detail = detail,
                            .severity = Severity::kDanger,
                    }
            );
        }

        return result;
    }

#else

    ProbeResult run_kernelpatch_supercall_latency_check() {
        ProbeResult result;
        result.extra_text = "";
        return result;
    }

#endif // aarch64

} // namespace duckdetector::nativeroot
