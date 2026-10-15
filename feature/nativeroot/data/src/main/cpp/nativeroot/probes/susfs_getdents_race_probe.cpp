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

#include "nativeroot/probes/susfs_getdents_race_probe.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <thread>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace duckdetector::nativeroot {
    namespace {

        // The susfs4ksu-lkm port filters /proc directory listings through a
        // compaction pass that runs with pagefaults disabled; on a user-access
        // fault it aborts and returns the ORIGINAL, unfiltered buffer. A second
        // thread flipping the buffer to PROT_NONE mid-syscall reliably triggers
        // that bail-out path, and mprotect preserves content, so the literal
        // hidden names survive in the buffer. A clean kernel never writes
        // "susfs"/"guard_lkm" entries into /proc at all.
        constexpr double kRaceBudgetSeconds = 5.0;
        constexpr size_t kBufferSize = 64 * 1024;

        struct RaceContext {
            uint8_t *buffer = nullptr;
            size_t length = 0;
            std::atomic<int> racing{0};
            std::atomic<int> settled{1};
            std::atomic<int> stop{0};
        };

        // Each toggle pair ends with PROT_READ|PROT_WRITE. When the toggler
        // observes `racing` cleared it parks and raises `settled`; from that
        // instant no mprotect can run until the driver re-arms `racing`, so
        // once the driver observes `settled` (and re-arms RW itself) parsing
        // the buffer is safe. Sequentially-consistent atomics make the flag
        // protocol sequentially consistent.
        void toggler_loop(RaceContext &context) {
            for (;;) {
                if (context.stop.load()) {
                    break;
                }
                if (!context.racing.load()) {
                    context.settled.store(1);
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                    continue;
                }
                mprotect(context.buffer, context.length, PROT_NONE);
                mprotect(context.buffer, context.length, PROT_READ | PROT_WRITE);
            }
        }

        double monotonic_seconds() {
            const auto now = std::chrono::steady_clock::now();
            return std::chrono::duration<double>(now.time_since_epoch()).count();
        }

        bool contains_pattern(const uint8_t *data, size_t length, const char *pattern) {
            const size_t pattern_length = std::strlen(pattern);
            if (length < pattern_length) {
                return false;
            }
            return std::search(data, data + length, pattern, pattern + pattern_length) != data + length;
        }

        // Child-side race driver. Returns a single-line report consumed by the
        // parent through the pipe: "LEAK=<0|1> attempts=... faults=... zero_ino=...".
        int run_race_child(int report_fd) {
            const int dir_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (dir_fd < 0) {
                const std::string line = "ERROR=open /proc failed errno=" + std::to_string(errno) + "\n";
                write(report_fd, line.data(), line.size());
                _exit(1);
            }

            void *mapping = mmap(nullptr, kBufferSize, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mapping == MAP_FAILED) {
                close(dir_fd);
                const std::string line = "ERROR=mmap failed errno=" + std::to_string(errno) + "\n";
                write(report_fd, line.data(), line.size());
                _exit(1);
            }

            RaceContext context;
            context.buffer = static_cast<uint8_t *>(mapping);
            context.length = kBufferSize;

            std::thread toggler(toggler_loop, std::ref(context));

            const double start = monotonic_seconds();
            unsigned long attempts = 0;
            unsigned long faults = 0;
            unsigned long zero_inode_records = 0;
            int leaked = 0;

            while (monotonic_seconds() - start < kRaceBudgetSeconds) {
                if (lseek(dir_fd, 0, SEEK_SET) < 0) {
                    break;
                }
                context.settled.store(0);
                context.racing.store(1);
                const long read_bytes = syscall(__NR_getdents64, dir_fd, mapping, kBufferSize);
                context.racing.store(0);
                int spins = 0;
                while (!context.settled.load() && ++spins < 10000000) {
                    // The toggler parks within one toggle pair (~us).
                }
                mprotect(mapping, kBufferSize, PROT_READ | PROT_WRITE);

                ++attempts;
                if (read_bytes < 0) {
                    ++faults;
                    continue;
                }
                if (read_bytes == 0) {
                    continue;
                }

                const auto *data = static_cast<const uint8_t *>(mapping);
                if (contains_pattern(data, static_cast<size_t>(read_bytes), "susfs") ||
                    contains_pattern(data, static_cast<size_t>(read_bytes), "guard_lkm")) {
                    leaked = 1;
                    break;
                }
            }

            context.stop.store(1);
            toggler.join();
            munmap(mapping, kBufferSize);
            close(dir_fd);

            std::string line = "LEAK=" + std::to_string(leaked) +
                               " attempts=" + std::to_string(attempts) +
                               " faults=" + std::to_string(faults) +
                               " zero_ino=" + std::to_string(zero_inode_records) + "\n";
            write(report_fd, line.data(), line.size());
            _exit(0);
        }

        std::string read_all_from_fd(int fd) {
            std::string output;
            char chunk[512];
            for (;;) {
                const ssize_t got = read(fd, chunk, sizeof(chunk));
                if (got <= 0) {
                    break;
                }
                output.append(chunk, static_cast<size_t>(got));
            }
            return output;
        }

    }  // namespace

    ProbeResult run_susfs_getdents_race_probe() {
        ProbeResult result;
        result.numeric_value = static_cast<long>(SusfsGetdentsRaceOutcome::kNotObserved);

        int pipe_fds[2];
        if (pipe(pipe_fds) != 0) {
            result.extra_text = "Not run: pipe failed (errno=" + std::to_string(errno) + ").";
            return result;
        }

        const pid_t pid = fork();
        if (pid < 0) {
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            result.extra_text = "Not run: fork failed (errno=" + std::to_string(errno) + ").";
            return result;
        }

        if (pid == 0) {
            close(pipe_fds[0]);
            run_race_child(pipe_fds[1]);
            _exit(1);
        }

        close(pipe_fds[1]);
        const std::string child_report = read_all_from_fd(pipe_fds[0]);
        close(pipe_fds[0]);

        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            result.extra_text = "Not observed: waitpid failed (errno=" + std::to_string(errno) + ").";
            return result;
        }

        if (WIFSIGNALED(status)) {
            result.extra_text = "Not observed: probe child crashed (signal " +
                                std::to_string(WTERMSIG(status)) + ").";
            return result;
        }

        if (child_report.rfind("ERROR=", 0) == 0) {
            result.extra_text = "Not run: " + child_report.substr(6);
            return result;
        }

        if (child_report.rfind("LEAK=", 0) != 0) {
            result.extra_text = "Not observed: probe child returned no report.";
            return result;
        }

        const bool leaked = child_report.rfind("LEAK=1", 0) == 0;
        result.numeric_value = static_cast<long>(
                leaked ? SusfsGetdentsRaceOutcome::kLeaked : SusfsGetdentsRaceOutcome::kRanClean);
        result.extra_text = "Raced getdents64(/proc) against an mprotect toggler for " +
                            std::to_string(static_cast<int>(kRaceBudgetSeconds)) + "s. " +
                            child_report.substr(0, child_report.find_last_not_of("\n") + 1) +
                            (leaked ? " Hidden susfs names survived in the returned buffer."
                                    : " No hidden names recovered.");

        if (leaked) {
            result.flags.susfs = true;
            result.hit_count = 1;
            result.findings.push_back(
                    Finding{
                            .group = "SIDE_CHANNEL",
                            .label = "susfs LKM getdents64 race leak",
                            .value = "Leaked",
                            .detail = result.extra_text,
                            .severity = Severity::kDanger,
                    }
            );
        }
        result.checked_count = 1;
        return result;
    }

}  // namespace duckdetector::nativeroot
