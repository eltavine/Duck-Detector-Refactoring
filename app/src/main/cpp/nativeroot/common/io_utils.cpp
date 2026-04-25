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

#include "nativeroot/common/io_utils.h"

#include <array>
#include <cstddef>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace duckdetector::nativeroot {
    namespace {

        struct linux_dirent64 {
            std::uint64_t d_ino;
            std::int64_t d_off;
            unsigned short d_reclen;
            unsigned char d_type;
            char d_name[];
        };

        bool stat_path(const char *path, struct stat *stat_buffer, const int flags) {
#if defined(__aarch64__) || defined(__x86_64__)
            return syscall(__NR_newfstatat, AT_FDCWD, path, stat_buffer, flags) == 0;
#elif defined(__arm__) || defined(__i386__)
            return syscall(__NR_fstatat64, AT_FDCWD, path, stat_buffer, flags) == 0;
#else
            if (flags == 0) {
                return stat(path, stat_buffer) == 0;
            }
            return fstatat(AT_FDCWD, path, stat_buffer, flags) == 0;
#endif
        }

    }  // namespace

    int syscall_openat_readonly(const char *path, const int flags) {
        return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags));
    }

    ssize_t syscall_read_fd(const int fd, void *buffer, const size_t count) {
        return syscall(__NR_read, fd, buffer, count);
    }

    int syscall_close_fd(const int fd) {
        return static_cast<int>(syscall(__NR_close, fd));
    }

    int syscall_getdents64_fd(const int fd, void *buffer, const size_t count) {
#if defined(__NR_getdents64)
        return static_cast<int>(syscall(__NR_getdents64, fd, buffer, count));
#else
        (void)fd;
        (void)buffer;
        (void)count;
        return -1;
#endif
    }

    SyscallProbeResult probe_kill_zero(const pid_t pid) {
#if defined(__NR_kill)
        errno = 0;
        const long value = syscall(__NR_kill, pid, 0);
        return SyscallProbeResult{
                .value = value,
                .error = value >= 0 ? 0 : errno,
        };
#else
        (void) pid;
        return SyscallProbeResult{
                .value = -1,
                .error = ENOSYS,
        };
#endif
    }

    SyscallProbeResult probe_getsid(const pid_t pid) {
#if defined(__NR_getsid)
        errno = 0;
        const long value = syscall(__NR_getsid, pid);
        return SyscallProbeResult{
                .value = value,
                .error = value >= 0 ? 0 : errno,
        };
#else
        (void) pid;
        return SyscallProbeResult{
                .value = -1,
                .error = ENOSYS,
        };
#endif
    }

    SyscallProbeResult probe_getpgid(const pid_t pid) {
#if defined(__NR_getpgid)
        errno = 0;
        const long value = syscall(__NR_getpgid, pid);
        return SyscallProbeResult{
                .value = value,
                .error = value >= 0 ? 0 : errno,
        };
#else
        (void) pid;
        return SyscallProbeResult{
                .value = -1,
                .error = ENOSYS,
        };
#endif
    }

    SyscallProbeResult probe_sched_getscheduler(const pid_t pid) {
#if defined(__NR_sched_getscheduler)
        errno = 0;
        const long value = syscall(__NR_sched_getscheduler, pid);
        return SyscallProbeResult{
                .value = value,
                .error = value >= 0 ? 0 : errno,
        };
#else
        (void) pid;
        return SyscallProbeResult{
                .value = -1,
                .error = ENOSYS,
        };
#endif
    }

    SyscallProbeResult probe_pidfd_open(const pid_t pid) {
#if defined(__NR_pidfd_open)
        errno = 0;
        const long value = syscall(__NR_pidfd_open, pid, 0U);
        const int error = value >= 0 ? 0 : errno;
        if (value >= 0) {
            syscall_close_fd(static_cast<int>(value));
        }
        return SyscallProbeResult{
                .value = value,
                .error = error,
        };
#else
        (void) pid;
        return SyscallProbeResult{
                .value = -1,
                .error = ENOSYS,
        };
#endif
    }

    std::string trim_copy(std::string value) {
        for (size_t index = 0; index < value.size(); ++index) {
            if (value[index] == '\0' || value[index] == '\r' || value[index] == '\n') {
                value.erase(index);
                break;
            }
        }

        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
            value.erase(value.begin());
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
            value.pop_back();
        }
        return value;
    }

    std::string read_text_file(const char *path, const size_t max_size) {
        const int fd = syscall_openat_readonly(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            return "";
        }

        std::string content;
        content.resize(max_size);
        const ssize_t bytes_read = syscall_read_fd(fd, content.data(), max_size);
        syscall_close_fd(fd);

        if (bytes_read <= 0) {
            return "";
        }
        content.resize(static_cast<size_t>(bytes_read));
        return trim_copy(content);
    }

    std::string read_link_target(const char *path, const size_t max_size) {
        std::string content;
        content.resize(max_size);
        const ssize_t bytes_read = readlink(path, content.data(), max_size);
        if (bytes_read <= 0) {
            return "";
        }
        content.resize(static_cast<size_t>(bytes_read));
        return trim_copy(content);
    }

    bool file_exists(const char *path) {
        struct stat stat_buffer{};
        return stat_path(path, &stat_buffer, 0);
    }

    bool dir_exists(const char *path) {
        struct stat stat_buffer{};
        return stat_path(path, &stat_buffer, 0) && S_ISDIR(stat_buffer.st_mode);
    }

    bool path_exists_no_follow(const char *path) {
        struct stat stat_buffer{};
        return stat_path(path, &stat_buffer, AT_SYMLINK_NOFOLLOW);
    }

    bool path_openable(const char *path) {
        int fd = syscall_openat_readonly(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            fd = syscall_openat_readonly(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        }
        if (fd < 0) {
            return false;
        }
        syscall_close_fd(fd);
        return true;
    }

    bool directory_contains_entry(const char *directory_path, const char *entry_name) {
        if (directory_path == nullptr || entry_name == nullptr || entry_name[0] == '\0') {
            return false;
        }

        const int fd =
                syscall_openat_readonly(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
            return false;
        }

        std::array<char, 4096> buffer{};
        bool found = false;
        while (true) {
            const int bytes_read = syscall_getdents64_fd(fd, buffer.data(), buffer.size());
            if (bytes_read <= 0) {
                break;
            }

            int offset = 0;
            while (offset < bytes_read) {
                if (offset + static_cast<int>(offsetof(linux_dirent64, d_name)) >= bytes_read) {
                    offset = bytes_read;
                    break;
                }

                auto *entry = reinterpret_cast<linux_dirent64 *>(buffer.data() + offset);
                if (entry->d_reclen == 0 || offset + entry->d_reclen > bytes_read) {
                    offset = bytes_read;
                    break;
                }

                if (std::strcmp(entry->d_name, entry_name) == 0) {
                    found = true;
                    break;
                }

                offset += entry->d_reclen;
            }

            if (found) {
                break;
            }
        }

        syscall_close_fd(fd);
        return found;
    }

    std::string read_property_value(const char *name) {
        char value[PROP_VALUE_MAX] = {};
        if (__system_property_get(name, value) <= 0) {
            return "";
        }
        return trim_copy(std::string(value));
    }

    std::string lowercase_copy(std::string value) {
        for (char &ch: value) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        return value;
    }

    bool contains_ignore_case(const std::string &haystack, const char *needle) {
        return lowercase_copy(haystack).find(lowercase_copy(std::string(needle))) !=
               std::string::npos;
    }

    bool contains_any_ignore_case(
            const std::string &haystack,
            const std::initializer_list<const char *> needles
    ) {
        const std::string lowered = lowercase_copy(haystack);
        for (const char *needle: needles) {
            if (lowered.find(lowercase_copy(std::string(needle))) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    bool is_numeric_name(const char *name, const size_t max_length) {
        if (name == nullptr || name[0] == '\0') {
            return false;
        }
        for (size_t index = 0; index < max_length && name[index] != '\0'; ++index) {
            if (std::isdigit(static_cast<unsigned char>(name[index])) == 0) {
                return false;
            }
        }
        return true;
    }

}  // namespace duckdetector::nativeroot
