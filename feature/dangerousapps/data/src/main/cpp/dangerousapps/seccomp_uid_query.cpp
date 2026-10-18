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

#include "seccomp_uid_protocol.h"
#include "common/seccomp_child.h"
#include <array>
#include <cerrno>
#include <csignal>
#include <linux/seccomp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace duckdetector::dangerousapps::seccomp_uid {
namespace {
int64_t now_ms() {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return static_cast<int64_t>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

void query_trap(int, siginfo_t *info, void *) {
    // SIGSYS alone does not identify the syscall; setup calls may be refused too.
    const bool attributed = info != nullptr && info->si_code == SYS_SECCOMP &&
        info->si_syscall == __NR_getpriority && info->si_arch == kAuditArch;
    _exit(attributed ? kQueryTrapExit : duckdetector::common::kSeccompTrappedExitStatus);
}

int query_child(int listener_fd, pid_t coordinator, int first_uid, int last_uid) {
    // Parent death closes the listener, but an inherited foreign filter could still block forever.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != coordinator) return 1;
    struct sigaction action{};
    action.sa_sigaction = query_trap;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSYS, &action, nullptr) != 0) return 1;
    action.sa_handler = SIG_DFL;
    action.sa_flags = 0;
    if (sigaction(SIGALRM, &action, nullptr) != 0) return 1;
    itimerval timer{};
    timer.it_value.tv_sec = 3;
    if (syscall(SYS_setitimer, ITIMER_REAL, &timer, nullptr) != 0) return 1;
    close(listener_fd);
    for (int64_t uid = first_uid; uid <= last_uid; ++uid) {
        long value;
        do {
            errno = 0;
            value = syscall(SYS_getpriority, PRIO_USER, static_cast<int>(uid));
        } while (value == -1 && errno == EINTR);
    }
    return 0;
}

void stop_query(pid_t child) {
    kill(child, SIGKILL);
    const int64_t start = now_ms();
    int status = 0;
    // No blocking waitpid after SIGKILL; a task can remain temporarily unreapable.
    for (int attempts = 0; attempts < 250; ++attempts) {
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child || (waited < 0 && errno != EINTR)) return;
        const int64_t now = now_ms();
        if (start >= 0 && now >= 0 && now - start >= 250) return;
        const timespec interval{0, 1000000};
        nanosleep(&interval, nullptr);
    }
}
} // namespace

void service_queries(int listener_fd, int report_fd, int first_uid, int last_uid, Result &result) {
    const pid_t coordinator = getpid();
    const uid_t self = getuid();
    struct sigaction children{};
    children.sa_handler = SIG_DFL;
    sigemptyset(&children.sa_mask);
    if (sigaction(SIGCHLD, &children, nullptr) != 0) {
        result.query_outcome = kQueryFailure;
        result.query_error = errno;
        return;
    }
    const pid_t child = fork();
    if (child < 0) { result.query_outcome = kQueryFailure; result.query_error = errno; return; }
    if (child == 0) {
        close(report_fd);
        _exit(query_child(listener_fd, coordinator, first_uid, last_uid));
    }
    std::array<unsigned char, (kMaxSpan + 7) / 8> seen{};
    const int64_t start = now_ms();
    bool exited = false;
    int status = 0;
    result.query_outcome = kQueryFailure;
    for (;;) {
        const int64_t now = now_ms();
        if (start < 0 || now < 0) { result.query_error = EIO; break; }
        if (now - start >= 1800) { result.query_outcome = kQueryTimeout; result.query_error = ETIMEDOUT; break; }
        const pid_t reaped = waitpid(child, &status, WNOHANG);
        if (reaped == child) { exited = true; break; }
        if (reaped < 0) {
            if (errno == EINTR) continue;
            result.query_error = errno;
            // ECHILD means we cannot establish ownership; do not signal a potentially reused PID.
            if (errno == ECHILD) return;
            break;
        }
        pollfd descriptor{listener_fd, POLLIN, 0};
        const int ready = poll(&descriptor, 1, 20);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            result.query_error = ready < 0 ? errno : EIO;
            break;
        }
        if (ready == 0 || !(descriptor.revents & POLLIN)) continue;
        seccomp_notif notification{};
        const int received = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &notification);
        if (received < 0 && (errno == EINTR || errno == ENOENT)) continue;
        if (received < 0) { result.query_error = errno; break; }
        const int uid = static_cast<int>(notification.data.args[1]);
        if (notification.pid != static_cast<unsigned int>(child) || notification.data.arch != kAuditArch ||
            notification.data.nr != __NR_getpriority ||
            static_cast<int>(notification.data.args[0]) != PRIO_USER || uid < first_uid || uid > last_uid) {
            result.query_error = EPROTO;
            break;
        }
        seccomp_notif_resp response{};
        response.id = notification.id;
        // A synthetic success is sufficient to observe action precedence. flags=0 also works on
        // Linux 5.0; CONTINUE was added later and is unnecessary for this read-only experiment.
        int sent;
        do { sent = ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &response); }
        while (sent < 0 && errno == EINTR && now_ms() - start < 1800);
        if (sent < 0 && errno == ENOENT) continue;
        if (sent < 0) { result.query_error = errno; break; }
        const size_t index = static_cast<size_t>(uid - first_uid);
        const unsigned char bit = static_cast<unsigned char>(1u << (index % 8));
        if (!(seen[index / 8] & bit)) { seen[index / 8] |= bit; ++result.notified; }
        if (uid == static_cast<int>(self)) result.self_notified = 1;
    }
    if (!exited) { stop_query(child); return; }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        result.query_outcome = kQueryComplete;
        result.queried = last_uid - first_uid + 1;
        for (int index = 0; index < result.queried; ++index) {
            if (!(seen[index / 8] & (1u << (index % 8)))) {
                if (result.first_suppressed < 0) result.first_suppressed = first_uid + index;
                result.last_suppressed = first_uid + index;
            }
        }
    } else if (WIFEXITED(status) && WEXITSTATUS(status) == kQueryTrapExit) {
        result.query_outcome = kQueryTrapped;
        result.query_error = SIGSYS;
    } else if (WIFSIGNALED(status)) {
        result.query_outcome = WTERMSIG(status) == SIGALRM ? kQueryTimeout : kQuerySignaled;
        result.query_error = WTERMSIG(status);
    } else {
        result.query_error = WIFEXITED(status) &&
            WEXITSTATUS(status) == duckdetector::common::kSeccompTrappedExitStatus ? SIGSYS : EPROTO;
    }
}
} // namespace duckdetector::dangerousapps::seccomp_uid
