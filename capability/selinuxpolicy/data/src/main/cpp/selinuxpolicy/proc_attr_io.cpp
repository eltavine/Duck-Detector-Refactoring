// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/proc_attr_probe.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace duckdetector::selinux::proc_attr {
    namespace { constexpr char kCurrent[] = "/proc/thread-self/attr/current"; }
    int read_identity(char *context, const unsigned capacity) {
        if (capacity < 2) return EINVAL;
        const int fd = open(kCurrent, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return errno;
        ssize_t count;
        do { count = read(fd, context, capacity - 1); } while (count < 0 && errno == EINTR);
        const int error = count < 0 ? errno : 0;
        close(fd);
        if (count <= 0 || count >= static_cast<ssize_t>(capacity - 1)) return error ? error : EINVAL;
        while (count > 0 && (context[count - 1] == '\n' || context[count - 1] == '\0')) --count;
        context[count] = '\0';
        return count > 0 && std::strlen(context) == static_cast<size_t>(count) ? 0 : EINVAL;
    }
    WriteResult write_current(const char *context) {
        const int fd = open(kCurrent, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return {errno, 0, -2};
        // One transaction per fresh FD: retrying or appending a short write changes procfs semantics.
        const ssize_t bytes = write(fd, context, std::strlen(context));
        const int error = bytes < 0 ? errno : 0;
        close(fd);
        return {0, error, bytes};
    }
}
