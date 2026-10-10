// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/avc_lookup_probe.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sched.h>
#endif
static int open_error, open_flags, read_error, read_calls, write_calls, close_calls, write_errno;
static bool interrupt_once;
static const char *opened;
static std::string served;
static size_t offset;
static ssize_t write_result;
int test_open(const char *path, int flags) {
    opened = path;
    open_flags = flags;
    if (open_error) { errno = open_error; return -1; }
    offset = 0;
    return 7;
}
ssize_t test_read(int fd, void *buffer, size_t size) {
    assert(fd == 7);
    ++read_calls;
    if (interrupt_once) { interrupt_once = false; errno = EINTR; return -1; }
    if (read_error) { errno = read_error; return -1; }
    const size_t count = std::min({size, served.size() - offset, size_t{5}});
    memcpy(buffer, served.data() + offset, count);
    offset += count;
    return static_cast<ssize_t>(count);
}
ssize_t test_write(int fd, const void *, size_t size) {
    assert(fd == 7 && size == duckdetector::selinux::avc_lookup::kPayloadLength);
    ++write_calls;
    errno = write_errno;
    return write_result;
}
int test_close(int fd) { assert(fd == 7); ++close_calls; errno = EBADF; return -1; }
#define open test_open
#define read test_read
#define write test_write
#define close test_close
#include "selinuxpolicy/avc_lookup_io.cpp"
#undef open
#undef read
#undef write
#undef close
int main() {
    using namespace duckdetector::selinux::avc_lookup;
    char buffer[64]{};
    size_t length = 0;
    served = "0-11\n";
    interrupt_once = true;
    assert(read_text(kPossibleCpus, buffer, sizeof(buffer), length) == 0 && length == 5);
    assert(!strcmp(opened, kPossibleCpus) && open_flags == (O_RDONLY | O_CLOEXEC) && close_calls == 1);
    assert(read_text(kPossibleCpus, buffer, 5, length) == EOVERFLOW && length == 5 && close_calls == 2);
    read_error = EIO;
    assert(read_text(kStats, buffer, sizeof(buffer), length) == EIO && close_calls == 3);
    read_error = 0;
    open_error = ENOENT;
    read_calls = 0;
    assert(read_text(kStats, buffer, sizeof(buffer), length) == ENOENT && read_calls == 0 && close_calls == 3);
    open_error = 0;
    served = std::string("u:r:app_zygote:s0\0", 18);
    assert(read_identity(buffer, sizeof(buffer)) == 0 && !strcmp(buffer, kCarrier));
    assert(!strcmp(opened, "/proc/thread-self/attr/current") && open_flags == (O_RDONLY | O_CLOEXEC));
    served = "u:r:app_zygote:s0:c512,c768\n";
    assert(read_identity(buffer, sizeof(buffer)) == 0 && !strcmp(buffer, "u:r:app_zygote:s0:c512,c768"));
    served = "u:r:app_zygote:s0\n";
    assert(read_identity(buffer, sizeof(buffer)) == 0 && !strcmp(buffer, kCarrier));
    served = "u:r:app_zygote:s0";
    assert(read_identity(buffer, 10) == EOVERFLOW && read_identity(buffer, 1) == EINVAL);
    served = std::string("\n\0", 2);
    assert(read_identity(buffer, sizeof(buffer)) == EINVAL);
    int fd = -1;
    assert(open_attr(fd) == 0 && fd == 7 && open_flags == (O_WRONLY | O_CLOEXEC));
    open_error = EACCES;
    assert(open_attr(fd) == EACCES && fd == -1);
    open_error = 0;
    for (int error : {EINVAL, EACCES, EPERM, EINTR}) {
        write_errno = error;
        write_result = -1;
        write_calls = 0;
        const WriteOutcome outcome = write_payload(7, kPayloadA);
        // EINTR is not retried: a second write would be a second transaction.
        assert(outcome.error == error && outcome.bytes == -1 && write_calls == 1);
    }
    for (ssize_t count : {ssize_t{0}, ssize_t{3}, static_cast<ssize_t>(kPayloadLength)}) {
        write_errno = EBADF;
        write_result = count;
        const WriteOutcome outcome = write_payload(7, kPayloadB);
        assert(outcome.error == 0 && outcome.bytes == count);
    }
    close_calls = 0;
    close_attr(7);
    assert(close_calls == 1);
    uint64_t first = 0, second = 0;
    assert(now_ns(first) == 0 && now_ns(second) == 0 && second >= first);
    int cpu = 99;
#if defined(__linux__)
    assert(pin_to_allowed_cpu(cpu) == 0 && cpu >= 0 && verify_pinned(cpu) == 0);
#else
    assert(pin_to_allowed_cpu(cpu) == ENOSYS && cpu == -1 && verify_pinned(0) == ENOSYS);
#endif
}
