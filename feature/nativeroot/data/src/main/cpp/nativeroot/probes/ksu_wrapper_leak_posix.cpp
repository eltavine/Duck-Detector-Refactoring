#include "ksu_wrapper_leak_probe.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

namespace duckdetector::nativeroot {
namespace {
constexpr long kAnonInodeFs = 0x09041934;
constexpr long kDevptsFs = 0x1cd1;
class PosixWrapperIo final : public WrapperLeakIo {
public:
    int candidate = -1;
    int direct = -1;
    std::string reopen;
    WrapperStage stage = WrapperStage::kUnavailable;
    int saved_error = 0;
    const std::chrono::steady_clock::time_point deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(8);
    bool fail(WrapperStage value, int code) { stage = value; saved_error = code; return false; }
    bool check_deadline() {
        return std::chrono::steady_clock::now() < deadline || fail(WrapperStage::kTimedOut, ETIMEDOUT);
    }
    bool io_error() {
        return fail(errno == EACCES || errno == EPERM ? WrapperStage::kPermissionLimited :
                    WrapperStage::kIoFailed, errno);
    }
    bool close_owned(int &fd) {
        if (fd < 0) return true;
        const int owned = fd;
        fd = -1;
        // Linux close releases the descriptor even on EINTR. Never retry a reused fd.
        if (close(owned) == 0) return true;
        return fail(WrapperStage::kCleanupFailed, errno);
    }
    bool cleanup() override {
        const bool first = close_owned(direct);
        const bool second = close_owned(candidate);
        return first && second;
    }
    ~PosixWrapperIo() override { cleanup(); }
    WrapperStage failure() const override { return stage; }
    int error() const override { return saved_error; }
    bool settle(int milliseconds) override {
        if (!check_deadline()) return false;
        timespec delay{milliseconds / 1000, (milliseconds % 1000) * 1000000L};
        while (nanosleep(&delay, &delay) < 0) {
            if (errno != EINTR) return io_error();
            if (!check_deadline()) return false;
        }
        return check_deadline();
    }
    bool counter(FileNrPoint &point) override {
        std::array<int64_t, 5> values{};
        for (auto &value : values) {
            if (!check_deadline()) return false;
            int fd = open("/proc/sys/fs/file-nr", O_RDONLY | O_CLOEXEC);
            if (fd < 0) return io_error();
            char buffer[128]{};
            ssize_t length;
            do { length = read(fd, buffer, sizeof(buffer) - 1); } while (length < 0 && errno == EINTR && check_deadline());
            const int read_error = errno;
            if (!close_owned(fd)) return false;
            if (length < 0) { errno = read_error; return io_error(); }
            if (length == static_cast<ssize_t>(sizeof(buffer) - 1) ||
                std::memchr(buffer, 0, static_cast<size_t>(length)) != nullptr || !parse_file_nr(buffer, value))
                return fail(WrapperStage::kMalformedCounter, EINVAL);
            if (!settle(10)) return false;
        }
        std::sort(values.begin(), values.end());
        point = {values[2], values[4] - values[0]};
        return true;
    }
    bool cycles(bool wrapped, int count, int &completed) override {
        // Both paths open the same PTY, without I/O or controlling-terminal acquisition.
        const char *path = wrapped ? reopen.c_str() : terminal.c_str();
        for (int i = 0; i < count; ++i) {
            if (!check_deadline()) return false;
            int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
            if (fd < 0) return io_error();
            ++completed;
            if (!close_owned(fd)) return false;
        }
        return true;
    }
    std::string terminal;
};

bool terminal_path(const char *path) {
    constexpr const char *prefix = "/dev/pts/";
    if (std::strncmp(path, prefix, std::strlen(prefix)) != 0) return false;
    path += std::strlen(prefix);
    if (!*path) return false;
    for (; *path; ++path) if (*path < '0' || *path > '9') return false;
    return true;
}
}
WrapperLeakSample collect_wrapper_leak() {
    PosixWrapperIo io;
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) { io.io_error(); return {io.failure(), io.error()}; }
    bool enumeration_ok = true;
    while (io.check_deadline()) {
        errno = 0;
        dirent *entry = readdir(directory);
        if (!entry) { if (errno) { io.io_error(); enumeration_ok = false; } break; }
        char *end = nullptr;
        long number = std::strtol(entry->d_name, &end, 10);
        if (!*entry->d_name || *end || number < 0 || number > 0x7fffffff) continue;
        // A dup pins the original file without executing the wrapper's leaking open path.
        int owned = fcntl(static_cast<int>(number), F_DUPFD_CLOEXEC, 0);
        if (owned < 0) {
            if (errno == EBADF) continue; // Concurrently closed original descriptor.
            io.io_error(); enumeration_ok = false; break;
        }
        struct stat status{};
        struct statfs fs{};
        bool eligible = false;
        if (fstat(owned, &status) < 0) { io.io_error(); enumeration_ok = false; }
        else if (S_ISCHR(status.st_mode)) {
            if (fstatfs(owned, &fs) < 0) { io.io_error(); enumeration_ok = false; }
            else if (fs.f_type == kAnonInodeFs) {
                char link[64]{};
                const std::string proc = "/proc/self/fd/" + std::to_string(owned);
                const auto length = readlink(proc.c_str(), link, sizeof(link) - 1);
                if (length < 0) { io.io_error(); enumeration_ok = false; }
                else eligible = length > 0 && length < static_cast<ssize_t>(sizeof(link) - 1) && terminal_path(link);
                if (eligible) { io.candidate = owned; io.reopen = proc; io.terminal = link; break; }
            }
        }
        if (!io.close_owned(owned)) enumeration_ok = false;
        if (!enumeration_ok) break;
    }
    if (closedir(directory) != 0) { io.io_error(); enumeration_ok = false; }
    if (!io.check_deadline()) enumeration_ok = false;
    if (!enumeration_ok || io.candidate < 0) {
        WrapperLeakSample result;
        result.stage = enumeration_ok ? WrapperStage::kNoCandidate : io.failure();
        result.error = io.error();
        if (!io.cleanup()) { result.stage = WrapperStage::kCleanupFailed; result.error = io.error(); }
        return result;
    }
    io.direct = open(io.terminal.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    struct statfs fs{};
    if (io.direct < 0) io.io_error();
    else if (fstatfs(io.direct, &fs) != 0) io.io_error();
    else if (fs.f_type == kDevptsFs && isatty(io.direct) == 1 && isatty(io.candidate) == 1)
        return sample_wrapper_leak(io);
    else io.fail(WrapperStage::kUnavailable, ENOTTY);
    WrapperLeakSample result;
    result.stage = io.failure(); result.error = io.error();
    if (!io.cleanup()) { result.stage = WrapperStage::kCleanupFailed; result.error = io.error(); }
    return result;
}
}
