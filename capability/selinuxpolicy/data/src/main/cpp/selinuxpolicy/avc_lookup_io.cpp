// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/avc_lookup_probe.h"
#include <cerrno>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sched.h>
#endif

namespace duckdetector::selinux::avc_lookup {
    namespace {
        constexpr char kAttr[] = "/proc/thread-self/attr/current";
    }

    int read_text(const char *path, char *buffer, const size_t capacity, size_t &length) {
        length = 0;
        const int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return errno;
        int error = 0;
        while (length < capacity) {
            const ssize_t count = read(fd, buffer + length, capacity - length);
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) {
                error = errno;
                break;
            }
            if (count == 0) break;
            length += static_cast<size_t>(count);
        }
        close(fd);
        // A full buffer cannot tell a complete file from a truncated one.
        return error ? error : length == capacity ? EOVERFLOW : 0;
    }

    int read_identity(char *context, const unsigned capacity) {
        if (capacity < 2) return EINVAL;
        size_t length = 0;
        if (const int error = read_text(kAttr, context, capacity - 1, length)) return error;
        // selinux_getprocattr returns the context with its terminating NUL.
        while (length > 0 && (context[length - 1] == '\n' || context[length - 1] == '\0')) --length;
        context[length] = '\0';
        return length > 0 ? 0 : EINVAL;
    }

    int open_attr(int &fd) {
        fd = open(kAttr, O_WRONLY | O_CLOEXEC);
        return fd < 0 ? errno : 0;
    }

    // One write per call and no retry: proc_pid_attr_write treats every call as a new transaction.
    WriteOutcome write_payload(const int fd, const char *payload) {
        const ssize_t count = write(fd, payload, kPayloadLength);
        return count < 0 ? WriteOutcome{errno, -1} : WriteOutcome{0, static_cast<int64_t>(count)};
    }

    void close_attr(const int fd) { close(fd); }

    int now_ns(uint64_t &value) {
        timespec time{};
        if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) return errno;
        value = static_cast<uint64_t>(time.tv_sec) * 1000000000ULL + static_cast<uint64_t>(time.tv_nsec);
        return 0;
    }

#if defined(__linux__)
    int pin_to_allowed_cpu(int &cpu) {
        cpu = -1;
        cpu_set_t allowed;
        CPU_ZERO(&allowed);
        if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) return errno;
        for (int candidate = 0; candidate < CPU_SETSIZE; ++candidate) {
            if (!CPU_ISSET(candidate, &allowed)) continue;
            cpu_set_t target;
            CPU_ZERO(&target);
            CPU_SET(candidate, &target);
            if (sched_setaffinity(0, sizeof(target), &target) != 0) continue;
            cpu = candidate;
            return verify_pinned(candidate);
        }
        return ESRCH;
    }

    // A cpuset move resets the affinity of the tasks it moves (cpuset_attach_task), and a paused or
    // offline CPU pushes them elsewhere (select_fallback_rq), so being on the CPU now is not enough.
    int verify_pinned(const int cpu) {
        cpu_set_t current;
        CPU_ZERO(&current);
        if (sched_getaffinity(0, sizeof(current), &current) != 0) return errno;
        const int running = sched_getcpu();
        if (running < 0) return errno;
        return running == cpu && CPU_COUNT(&current) == 1 && CPU_ISSET(cpu, &current) ? 0 : EXDEV;
    }
#else
    // The counters are per CPU on Linux; other hosts build this adapter only for its tests.
    int pin_to_allowed_cpu(int &cpu) {
        cpu = -1;
        return ENOSYS;
    }

    int verify_pinned(int) { return ENOSYS; }
#endif
}
