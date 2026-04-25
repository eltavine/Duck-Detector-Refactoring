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

#include "zygisk/probes/seccomp_probe.h"

#include <cstddef>
#include <csignal>
#include <csetjmp>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/seccomp.h>

namespace duckdetector::zygisk {

    namespace {

        thread_local sigjmp_buf *g_jump_buffer = nullptr;
        thread_local int *g_triggered_syscall = nullptr;

        constexpr int available_nr(const int value) {
            return value;
        }

#if defined(__NR_getpid)
        constexpr int kGetPidNr = available_nr(__NR_getpid);
#else
        constexpr int kGetPidNr = -1;
#endif

#if defined(__NR_gettid)
        constexpr int kGetTidNr = available_nr(__NR_gettid);
#else
        constexpr int kGetTidNr = -1;
#endif

#if defined(__NR_munmap)
        constexpr int kMunmapNr = available_nr(__NR_munmap);
#else
        constexpr int kMunmapNr = -1;
#endif

        struct WorkerState {
            int write_fd = -1;
            bool supported = true;
            int triggered_syscall = 0;
        };

        struct WorkerPacket {
            int supported = 0;
            int triggered_syscall = 0;
        };

        const char *syscall_name(const int number) {
            switch (number) {
                case kGetPidNr:
                    return "getpid";
                case kGetTidNr:
                    return "gettid";
                case kMunmapNr:
                    return "munmap";
                default:
                    return "unknown";
            }
        }

        void sigsys_handler(
                int,
                siginfo_t *info,
                void *
        ) {
            if (g_triggered_syscall != nullptr) {
                *g_triggered_syscall = info != nullptr ? info->si_syscall : 0;
            }
            if (g_jump_buffer != nullptr) {
                siglongjmp(*g_jump_buffer, 1);
            }
        }

        void *worker_entry(void *raw_state) {
            auto *state = reinterpret_cast<WorkerState *>(raw_state);
            if (state == nullptr) {
                return nullptr;
            }

            const auto finish = [state](const bool restore_sigsys,
                                        const struct sigaction *old_action) -> void * {
                WorkerPacket packet{};
                packet.supported = state->supported ? 1 : 0;
                packet.triggered_syscall = state->triggered_syscall;
                if (state->write_fd >= 0) {
                    TEMP_FAILURE_RETRY(write(state->write_fd, &packet, sizeof(packet)));
                    close(state->write_fd);
                    state->write_fd = -1;
                }
                if (state->supported) {
                    syscall(__NR_exit, 0);
                }
                if (restore_sigsys && old_action != nullptr) {
                    sigaction(SIGSYS, old_action, nullptr);
                }
                return nullptr;
            };

            struct sigaction action{};
            struct sigaction old_action{};
            action.sa_sigaction = sigsys_handler;
            action.sa_flags = SA_SIGINFO;
            sigemptyset(&action.sa_mask);
            if (sigaction(SIGSYS, &action, &old_action) != 0) {
                state->supported = false;
                return finish(false, nullptr);
            }

            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                state->supported = false;
                return finish(true, &old_action);
            }

            sock_filter filter[] = {
                    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             static_cast<unsigned int>(offsetof(struct seccomp_data, nr))),
                    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned int>(kGetPidNr), 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
                    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned int>(kGetTidNr), 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
                    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned int>(kMunmapNr), 0, 1),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
                    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            };
            sock_fprog program{
                    .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
                    .filter = filter,
            };

            if (kGetPidNr < 0 || kGetTidNr < 0 || kMunmapNr < 0 ||
                prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
                state->supported = false;
                return finish(true, &old_action);
            }

            sigjmp_buf jump_buffer;
            g_jump_buffer = &jump_buffer;
            g_triggered_syscall = &state->triggered_syscall;
            if (sigsetjmp(jump_buffer, 1) == 0) {
                pthread_attr_t attributes;
                pthread_attr_init(&attributes);
                pthread_attr_setstacksize(&attributes, static_cast<size_t>(PTHREAD_STACK_MIN) * 2U);
                pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_JOINABLE);
                pthread_attr_destroy(&attributes);
            }
            g_jump_buffer = nullptr;
            g_triggered_syscall = nullptr;
            return finish(true, &old_action);
        }

    }  // namespace

    ProbeResult collect_seccomp_probe() {
        ProbeResult result;
        int pipe_fds[2] = {-1, -1};
        if (pipe(pipe_fds) != 0) {
            result.supported = false;
            return result;
        }
        fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC);
        fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

        WorkerState state;
        state.write_fd = pipe_fds[1];
        pthread_t worker{};
        if (pthread_create(&worker, nullptr, worker_entry, &state) != 0) {
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            result.supported = false;
            return result;
        }
        close(pipe_fds[1]);

        pollfd wait_fd{
                .fd = pipe_fds[0],
                .events = POLLIN,
                .revents = 0,
        };
        const int poll_result = TEMP_FAILURE_RETRY(poll(&wait_fd, 1, 500));
        WorkerPacket packet{};
        if (poll_result <= 0 ||
            TEMP_FAILURE_RETRY(read(pipe_fds[0], &packet, sizeof(packet))) != sizeof(packet)) {
            close(pipe_fds[0]);
            result.supported = false;
            return result;
        }
        close(pipe_fds[0]);

        pthread_detach(worker);

        result.supported = packet.supported != 0;
        if (!result.supported) {
            return result;
        }

        if (packet.triggered_syscall != 0) {
            result.traces.push_back({
                                            SignalGroup::kRuntime,
                                            SignalSeverity::kDanger,
                                            "Seccomp trap",
                                            std::string(
                                                    "pthread_attr_setstacksize triggered the ") +
                                            syscall_name(packet.triggered_syscall) +
                                            " syscall under a seccomp trap, which should not happen for the stock libc fast path.",
                                    });
            result.hit_count = 1;
            result.strong_hits = 1;
        }

        return result;
    }

}  // namespace duckdetector::zygisk
