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

#include <jni.h>
#include "common/disposable_child.h"
#include "common/seccomp_child.h"

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace {
constexpr int kMaxSpan = 10000;
constexpr int kVersion = 1;

// install_status, mirrored by HmaSeccompUidBridge.
constexpr int kInstalled = 0;
constexpr int kForeignListener = 1;
constexpr int kUnsupported = 2;
constexpr int kRestricted = 3;
constexpr int kFailure = 4;
constexpr int kInstallTrapped = 5;

// query_outcome, mirrored by HmaSeccompUidBridge.
constexpr int kQueryComplete = 0;
constexpr int kQueryTrapped = 1;
constexpr int kQuerySignaled = 2;
constexpr int kQueryTimeout = 3;
constexpr int kQueryFailure = 4;
constexpr int kQueryNotRun = 5;

constexpr int64_t kQueryDeadlineMs = 1800;
constexpr int kPollSliceMs = 20;

struct Result {
    int version;
    int install_status;
    int install_error;
    int kernel_major;
    int kernel_minor;
    int queried;
    int notified;
    int first_suppressed;
    int last_suppressed;
    int query_outcome;
    int query_error;
    int self_notified;
};

int64_t monotonic_ms() {
    timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return static_cast<int64_t>(value.tv_sec) * 1000 + value.tv_nsec / 1000000;
}

bool write_result(int fd, const Result &result) {
    const auto *data = reinterpret_cast<const unsigned char *>(&result);
    size_t written = 0;
    while (written < sizeof(result)) {
        const ssize_t count = write(fd, data + written, sizeof(result) - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        written += static_cast<size_t>(count);
    }
    return true;
}

void read_kernel_version(Result &result) {
    utsname release{};
    if (syscall(SYS_uname, &release) != 0) return;
    const char *cursor = release.release;
    int major = 0;
    int minor = 0;
    while (*cursor >= '0' && *cursor <= '9') {
        if (major > 100000) break;
        major = major * 10 + (*cursor - '0');
        ++cursor;
    }
    if (*cursor == '.') {
        ++cursor;
        while (*cursor >= '0' && *cursor <= '9') {
            if (minor > 100000) break;
            minor = minor * 10 + (*cursor - '0');
            ++cursor;
        }
    }
    if (major > 0) {
        result.kernel_major = major;
        result.kernel_minor = minor;
    }
}

int classify_install_error(int error) {
    switch (error) {
        case EBUSY: return kForeignListener;
        case EINVAL:
        case ENOSYS: return kUnsupported;
        case EPERM:
        case EACCES: return kRestricted;
        default: return kFailure;
    }
}

// Returns the listener fd or -1 with errno copied to error. The filter matches only
// getpriority(PRIO_USER, *), whose notification arrives before the syscall runs.
int install_listener(int *error) {
    // All supported Android ABIs are little-endian, so the 32-bit load at args[0] is the low
    // word of the int that carries PRIO_USER. The query child has the same ABI as this filter.
    sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpriority, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PRIO_USER, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{};
    program.len = static_cast<unsigned short>(sizeof(code) / sizeof(code[0]));
    program.filter = code;
    if (syscall(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 &&
        syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        *error = errno;
        return -1;
    }
    errno = 0;
    const long fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                            SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    if (fd < 0) {
        *error = errno;
        return -1;
    }
    *error = 0;
    return static_cast<int>(fd);
}

// Runs in the forked query child. The interval timer bounds an orphaned child if the probe child
// dies before it can service a notification. Only async-signal-safe calls are used.
int query_child(int listener_fd, int first_uid, int last_uid) {
    signal(SIGALRM, SIG_DFL);
    itimerval timer{};
    timer.it_value.tv_sec = 3;
    syscall(SYS_setitimer, ITIMER_REAL, &timer, nullptr);
    close(listener_fd);
    for (int uid = first_uid; uid <= last_uid; ++uid) {
        for (;;) {
            errno = 0;
            const long value = syscall(SYS_getpriority, PRIO_USER, uid);
            if (value == -1 && errno == EINTR) continue;
            break;
        }
    }
    return 0;
}

void wait_for_query_child(int listener_fd, pid_t child, int first_uid, int last_uid,
                          Result &result) {
    std::array<unsigned char, (kMaxSpan + 7) / 8> seen{};
    bool notification_error = false;
    const int64_t start = monotonic_ms();
    int status = 0;
    for (;;) {
        const pid_t reaped = waitpid(child, &status, WNOHANG);
        if (reaped == child) break;
        if (reaped < 0) {
            result.query_outcome = kQueryFailure;
            result.query_error = errno;
            return;
        }
        pollfd descriptor{listener_fd, POLLIN, 0};
        int ready;
        do {
            ready = poll(&descriptor, 1, kPollSliceMs);
        } while (ready < 0 && errno == EINTR);
        if (ready < 0) {
            notification_error = true;
            result.query_error = errno;
        }
        if (ready > 0 && (descriptor.revents & POLLIN) != 0) {
            seccomp_notif notification{};
            int received;
            do {
                received = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &notification);
            } while (received < 0 && errno == EINTR);
            if (received == 0) {
                if (notification.data.nr == __NR_getpriority &&
                    static_cast<int>(notification.data.args[0]) == PRIO_USER) {
                    const int uid = static_cast<int>(notification.data.args[1]);
                    if (uid >= first_uid && uid <= last_uid) {
                        const size_t index = static_cast<size_t>(uid - first_uid);
                        const unsigned char bit = static_cast<unsigned char>(1u << (index % 8));
                        if ((seen[index / 8] & bit) == 0) {
                            seen[index / 8] |= bit;
                            ++result.notified;
                        }
                    }
                    if (uid == static_cast<int>(syscall(SYS_getuid))) result.self_notified = 1;
                }
                seccomp_notif_resp response{};
                response.id = notification.id;
                response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                int sent;
                do {
                    sent = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &response);
                } while (sent < 0 && errno == EINTR);
                // ENOENT means the syscall was interrupted or already answered; the query child
                // retries EINTR, and a non-EINTR path is handled below.
                if (sent < 0 && errno != ENOENT) {
                    notification_error = true;
                    result.query_error = errno;
                }
            } else if (errno != ENOENT) {
                notification_error = true;
                result.query_error = errno;
            }
        }
        if (monotonic_ms() - start > kQueryDeadlineMs) {
            result.query_outcome = kQueryTimeout;
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            return;
        }
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        if (notification_error) {
            result.query_outcome = kQueryFailure;
            return;
        }
        result.query_outcome = kQueryComplete;
        result.queried = last_uid - first_uid + 1;
        for (int index = 0; index < result.queried; ++index) {
            if ((seen[index / 8] & (1u << (index % 8))) == 0) {
                const int uid = first_uid + index;
                if (result.first_suppressed < 0) result.first_suppressed = uid;
                result.last_suppressed = uid;
            }
        }
    } else if (WIFEXITED(status) &&
               WEXITSTATUS(status) == duckdetector::common::kSeccompTrappedExitStatus) {
        result.query_outcome = kQueryTrapped;
        result.query_error = SIGSYS;
    } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
        // SECCOMP_RET_KILL_PROCESS cannot be caught, so the query child dies by SIGSYS instead of
        // reaching the trap handler's 125 exit status. It is still a seccomp refusal.
        result.query_outcome = kQueryTrapped;
        result.query_error = SIGSYS;
    } else if (WIFSIGNALED(status)) {
        result.query_outcome = kQuerySignaled;
        result.query_error = WTERMSIG(status);
    } else {
        result.query_outcome = kQueryFailure;
        result.query_error = EPROTO;
    }
}

// This body runs after fork: fixed-size data and async-signal-safe platform calls only.
int collect(int fd, int first_uid, int last_uid) {
    Result result{};
    result.version = kVersion;
    result.first_suppressed = -1;
    result.last_suppressed = -1;
    result.query_outcome = kQueryNotRun;
    read_kernel_version(result);

    int install_error = 0;
    const int listener_fd = install_listener(&install_error);
    if (listener_fd < 0) {
        result.install_status = classify_install_error(install_error);
        result.install_error = install_error;
        return write_result(fd, result) ? 0 : 1;
    }
    result.install_status = kInstalled;

    const pid_t child = fork();
    if (child < 0) {
        result.install_status = kFailure;
        result.install_error = errno;
        close(listener_fd);
        return write_result(fd, result) ? 0 : 1;
    }
    if (child == 0) {
        _exit(query_child(listener_fd, first_uid, last_uid));
    }

    wait_for_query_child(listener_fd, child, first_uid, last_uid, result);
    close(listener_fd);
    return write_result(fd, result) ? 0 : 1;
}

bool valid_result(const Result &result, int first_uid, int last_uid) {
    const int span = last_uid - first_uid + 1;
    if (result.version != kVersion || result.install_status < kInstalled ||
        result.install_status > kInstallTrapped || result.kernel_major < 0 ||
        result.kernel_minor < 0 || result.queried < 0 || result.queried > span ||
        result.notified < 0 || result.notified > span ||
        result.query_outcome < kQueryComplete || result.query_outcome > kQueryNotRun ||
        (result.self_notified != 0 && result.self_notified != 1)) return false;
    if (result.install_status != kInstalled) {
        return result.queried == 0 && result.notified == 0 &&
               result.first_suppressed == -1 && result.last_suppressed == -1 &&
               result.query_outcome == kQueryNotRun && result.self_notified == 0;
    }
    if (result.query_outcome == kQueryComplete) {
        if (result.queried != span || result.notified > result.queried) return false;
        if (result.notified == result.queried) {
            return result.first_suppressed == -1 && result.last_suppressed == -1;
        }
        return result.first_suppressed >= first_uid &&
               result.first_suppressed <= result.last_suppressed &&
               result.last_suppressed <= last_uid;
    }
    return result.queried == 0 && result.first_suppressed == -1 &&
           result.last_suppressed == -1;
}
} // namespace

extern "C" JNIEXPORT jintArray JNICALL
Java_com_eltavine_duckdetector_features_dangerousapps_data_probes_hma_HmaSeccompUidBridge_nativeProbe(
        JNIEnv *env, jobject, jint first_uid, jint last_uid) {
    Result result{};
    result.version = kVersion;
    result.first_suppressed = -1;
    result.last_suppressed = -1;
    result.query_outcome = kQueryNotRun;
    if (first_uid < 0 || last_uid < first_uid ||
        static_cast<int64_t>(last_uid) - static_cast<int64_t>(first_uid) >= kMaxSpan) {
        result.install_status = kFailure;
        result.install_error = EINVAL;
    } else {
        std::array<unsigned char, sizeof(Result)> buffer{};
        const auto outcome = duckdetector::common::run_disposable_child(
            buffer,
            duckdetector::common::ChildDeadlines{std::chrono::milliseconds{2500},
                                                 std::chrono::milliseconds{250}},
            [first_uid, last_uid](int fd) { return collect(fd, first_uid, last_uid); });
        using duckdetector::common::ChildEnd;
        if (outcome.end == ChildEnd::kExited && outcome.exit_status == 0 &&
            outcome.report_length == sizeof(Result)) {
            std::memcpy(&result, buffer.data(), sizeof(result));
            if (!valid_result(result, first_uid, last_uid)) {
                result = Result{};
                result.version = kVersion;
                result.install_status = kFailure;
                result.install_error = EPROTO;
                result.first_suppressed = -1;
                result.last_suppressed = -1;
                result.query_outcome = kQueryNotRun;
            }
        } else {
            result.install_status = outcome.end == ChildEnd::kSeccompTrapped
                ? kInstallTrapped : kFailure;
            result.install_error = outcome.signal != 0 ? outcome.signal : outcome.error;
        }
    }
    const std::array<jint, 12> values{
        result.version, result.install_status, result.install_error,
        result.kernel_major, result.kernel_minor, result.queried, result.notified,
        result.first_suppressed, result.last_suppressed, result.query_outcome,
        result.query_error, result.self_notified,
    };
    jintArray output = env->NewIntArray(static_cast<jsize>(values.size()));
    if (output != nullptr) {
        env->SetIntArrayRegion(output, 0, static_cast<jsize>(values.size()), values.data());
    }
    return output;
}
