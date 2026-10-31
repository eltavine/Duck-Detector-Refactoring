#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include <vector>

// Compile the production POSIX adapter against deterministic syscall replacements.
// No real procfs/PTY opens or leak-triggering kernel operations run in this harness.
#ifndef TIOCGDEV
#define TIOCGDEV _IOR('T', 0x32, unsigned int)
#endif
namespace {
int opened = 100, ioctl_error = 0;
unsigned int candidate_device = 7, opened_device = 7;
bool swapped = false;
std::vector<int> closed;
int fake_open(const char *, int, ...) { return opened++; }
int fake_close(int fd) { closed.push_back(fd); return 0; }
int fake_ioctl(int fd, unsigned long request, ...) {
    assert(request == TIOCGDEV);
    if (ioctl_error) { errno = ioctl_error; return -1; }
    va_list args;
    va_start(args, request);
    *va_arg(args, unsigned int *) = fd == 1 ? candidate_device : fd == 2 ? 7 : opened_device;
    va_end(args);
    return 0;
}
int fake_fstat(int fd, struct stat *out) {
    *out = {};
    out->st_dev = 1;
    out->st_ino = swapped && fd >= 100 ? 9 : 2;
    out->st_rdev = 7;
    return 0;
}
}
#define open fake_open
#define close fake_close
#define ioctl fake_ioctl
#define fstat(fd, out) fake_fstat(fd, out)
#include "ksu_wrapper_leak_posix.cpp"
#undef open
#undef close
#undef ioctl
#undef fstat

using namespace duckdetector::nativeroot;
int main() {
    PosixWrapperIo io;
    io.candidate = 1; io.direct = 2; io.terminal = "/dev/pts/1"; io.reopen = "/proc/self/fd/1";
    assert(io.prepare_terminal());
    int completed = 0;
    assert(io.cycles(false, 2, completed) && completed == 2 && closed.size() == 2);
    completed = 0;
    assert(io.cycles(true, 2, completed) && completed == 2 && closed.size() == 4);
    swapped = true;
    completed = 0;
    assert(!io.cycles(false, 2, completed) && completed == 1 && io.error() == ESTALE && closed.size() == 5);
    swapped = false;
    opened_device = 8;
    completed = 0;
    assert(!io.cycles(true, 2, completed) && completed == 1 && io.error() == EXDEV && closed.size() == 6);
    opened_device = 7;
    candidate_device = 8;
    assert(!io.prepare_terminal() && io.error() == EXDEV);
    candidate_device = 7;
    ioctl_error = EACCES;
    assert(!io.prepare_terminal() && io.failure() == WrapperStage::kPermissionLimited);
    assert(io.cleanup());
    assert(closed[closed.size()-2] == 2 && closed.back() == 1);
}
