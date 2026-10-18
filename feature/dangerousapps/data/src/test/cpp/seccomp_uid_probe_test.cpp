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
#include "common/disposable_child.h"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

using namespace duckdetector::dangerousapps::seccomp_uid;
namespace {
enum class Scenario { Baseline, Errno, Listener, QueryTrap, SetupTrap, Kill, Interrupted };
struct Report { Result result; };

bool set_policy(Scenario scenario, int uid) {
    if (scenario == Scenario::Baseline) return true;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
    if (scenario == Scenario::Listener) {
        sock_filter code[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
        sock_fprog program{1, code};
        return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program) >= 0;
    }
    const unsigned int number = scenario == Scenario::SetupTrap ? __NR_setitimer : __NR_getpriority;
    const unsigned int action = scenario == Scenario::Errno ? SECCOMP_RET_ERRNO | EACCES :
        scenario == Scenario::Interrupted ? SECCOMP_RET_ERRNO | EINTR :
        scenario == Scenario::Kill ? SECCOMP_RET_KILL_PROCESS : SECCOMP_RET_TRAP;
    // Only the single selected UID is suppressed in the ERRNO experiment.
    sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned int>(uid), 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    if (scenario != Scenario::Errno) {
        // Other experiments match the syscall irrespective of its arguments.
        code[1] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 2, 3);
    }
    sock_fprog program{6, code};
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0;
}

bool descendants_gone() {
    int status = 0;
    for (int attempt = 0; attempt < 500; ++attempt) {
        const pid_t child = waitpid(-1, &status, WNOHANG);
        if (child < 0 && errno == ECHILD) return true;
        const timespec pause{0, 1000000};
        nanosleep(&pause, nullptr);
    }
    return false;
}

bool run_case(Scenario scenario) {
    const int first = static_cast<int>(getuid());
    std::array<unsigned char, sizeof(Report)> bytes{};
    auto outcome = duckdetector::common::run_disposable_child(bytes,
        duckdetector::common::ChildDeadlines{std::chrono::milliseconds{6000}, std::chrono::milliseconds{250}},
        [=](int fd) {
            if (!set_policy(scenario, first + 1)) return 2;
            Report report{run_probe(first, first + 2)};
            return write(fd, &report, sizeof(report)) == sizeof(report) ? 0 : 3;
        });
    if (outcome.end != duckdetector::common::ChildEnd::kExited || outcome.exit_status != 0 ||
        outcome.report_length != sizeof(Report)) return false;
    Report report{};
    std::memcpy(&report, bytes.data(), sizeof(report));
    const auto &r = report.result;
    std::printf("  install=%d query=%d queries=%d notifications=%d errors=%d/%d\n",
        r.install_status, r.query_outcome, r.queried, r.notified, r.install_error, r.query_error);
    switch (scenario) {
        case Scenario::Baseline: return r.install_status == kInstalled && r.query_outcome == kQueryComplete && r.notified == 3;
        case Scenario::Errno: return r.install_status == kInstalled && r.query_outcome == kQueryComplete &&
            r.notified == 2 && r.first_suppressed == first + 1 && r.last_suppressed == first + 1;
        case Scenario::Listener: return r.install_status == kForeignListener && r.install_error == EBUSY;
        case Scenario::QueryTrap: return r.install_status == kInstalled && r.query_outcome == kQueryTrapped;
        case Scenario::SetupTrap: return r.install_status == kInstalled && r.query_outcome == kQueryFailure && r.query_error == SIGSYS;
        case Scenario::Kill: return r.install_status == kInstalled && r.query_outcome == kQuerySignaled && r.query_error == SIGSYS;
        case Scenario::Interrupted: return r.install_status == kInstalled && r.query_outcome == kQueryTimeout;
    }
    return false;
}
bool coordinator_death_case() {
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
    sock_filter notify[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpriority, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{4, notify};
    const int listener = static_cast<int>(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_NEW_LISTENER, &program));
    if (listener < 0) return false;
    const int uid = static_cast<int>(getuid());
    const pid_t coordinator = fork();
    if (coordinator == 0) {
        // Keep the coordinator from consuming the notification before the test supervisor sees it.
        sock_filter interrupt_poll[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ppoll, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EINTR),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        sock_fprog pause{4, interrupt_poll};
        if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &pause) != 0) _exit(2);
        Result result{};
        service_queries(listener, -1, uid, uid + 2, result);
        _exit(0);
    }
    if (coordinator < 0) { close(listener); return false; }
    pollfd descriptor{listener, POLLIN, 0};
    seccomp_notif pending{};
    const bool blocked = poll(&descriptor, 1, 1000) > 0 &&
        ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &pending) == 0;
    // A live query is now blocked while this supervisor keeps the listener open.
    kill(coordinator, SIGKILL);
    int status = 0;
    while (waitpid(coordinator, &status, 0) < 0 && errno == EINTR) {}
    const bool cleaned = descendants_gone();
    if (!cleaned && blocked) { kill(static_cast<pid_t>(pending.pid), SIGKILL); descendants_gone(); }
    close(listener);
    return blocked && cleaned;
}
} // namespace

int main() {
    const std::array scenarios{Scenario::Baseline, Scenario::Errno, Scenario::Listener, Scenario::QueryTrap,
        Scenario::SetupTrap, Scenario::Kill, Scenario::Interrupted};
    int failures = 0;
    for (size_t index = 0; index < scenarios.size(); ++index) {
        const bool passed = run_case(scenarios[index]);
        std::printf("case %zu: %s\n", index, passed ? "PASS" : "FAIL");
        failures += !passed;
    }
    const bool cleaned = coordinator_death_case();
    std::printf("case 7 (coordinator death): %s\n", cleaned ? "PASS" : "FAIL");
    failures += !cleaned;
    return failures == 0 ? 0 : 1;
}
