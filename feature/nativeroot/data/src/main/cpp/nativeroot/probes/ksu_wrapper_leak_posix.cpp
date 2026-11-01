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
#include <sys/ioctl.h>
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
    std::chrono::steady_clock::time_point deadline;
    explicit PosixWrapperIo(std::chrono::steady_clock::time_point stop =
            std::chrono::steady_clock::now() + std::chrono::seconds(8)) : deadline(stop) {}
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
            size_t used = 0;
            bool read_ok = true;
            while (true) {
                if (!check_deadline()) { read_ok = false; break; }
                const ssize_t length = read(fd, buffer + used, sizeof(buffer) - 1 - used);
                if (length < 0) {
                    if (errno == EINTR) continue;
                    read_ok = io_error();
                    break;
                }
                if (length == 0) break;
                used += static_cast<size_t>(length);
                if (used == sizeof(buffer) - 1) {
                    read_ok = fail(WrapperStage::kMalformedCounter, EOVERFLOW);
                    break;
                }
            }
            if (!close_owned(fd) || !read_ok) return false;
            if (std::memchr(buffer, 0, used) != nullptr || !parse_file_nr(buffer, value))
                return fail(WrapperStage::kMalformedCounter, EINVAL);
            if (!settle(10)) return false;
        }
        std::sort(values.begin(), values.end());
        point = {values[2], values[4] - values[0]};
        return true;
    }
    struct stat terminal_identity{};
    unsigned int terminal_device = 0;
    bool device_number(int fd, unsigned int &device) {
        if (ioctl(fd, TIOCGDEV, &device) < 0) return io_error();
        return true;
    }
    bool tty_accessible(int fd) {
        if (isatty(fd) == 1) return true;
        if (errno == EACCES || errno == EPERM) return io_error();
        return fail(WrapperStage::kUnavailable, errno ? errno : ENOTTY);
    }
    bool prepare_terminal() {
        unsigned int candidate_device = 0;
        if (fstat(direct, &terminal_identity) < 0) return io_error();
        if (!device_number(direct, terminal_device) || !device_number(candidate, candidate_device)) return false;
        if (candidate_device != terminal_device) return fail(WrapperStage::kUnavailable, EXDEV);
        return true;
    }
    bool validate_terminal(int fd, bool wrapped) {
        unsigned int device = 0;
        if (!device_number(fd, device)) return false;
        if (device != terminal_device) return fail(WrapperStage::kUnavailable, EXDEV);
        if (!wrapped) {
            struct stat identity{};
            if (fstat(fd, &identity) < 0) return io_error();
            if (identity.st_dev != terminal_identity.st_dev || identity.st_ino != terminal_identity.st_ino ||
                identity.st_rdev != terminal_identity.st_rdev)
                return fail(WrapperStage::kUnavailable, ESTALE);
        }
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
            const bool valid = validate_terminal(fd, wrapped);
            if (!close_owned(fd) || !valid) return false;
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
    if (!io.check_deadline()) enumeration_ok = false;
    if (closedir(directory) != 0) { io.fail(WrapperStage::kCleanupFailed, errno); enumeration_ok = false; }
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
    else if (fs.f_type != kDevptsFs) io.fail(WrapperStage::kUnavailable, ENOTTY);
    else if (io.tty_accessible(io.direct) && io.tty_accessible(io.candidate) && io.prepare_terminal())
        return sample_wrapper_leak(io);
    WrapperLeakSample result;
    result.stage = io.failure(); result.error = io.error();
    if (!io.cleanup()) { result.stage = WrapperStage::kCleanupFailed; result.error = io.error(); }
    return result;
}
}
