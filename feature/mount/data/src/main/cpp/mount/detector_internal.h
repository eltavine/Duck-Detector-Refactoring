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

#pragma once

#include "common/seccomp_child.h"
#include "mount/detector_core.h"
#include <android/log.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/stat.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unordered_set>
#include <utility>
#include <vector>

#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xE0F5E1E2
#endif
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

namespace duckdetector::mount::detail {

    constexpr char kLogTag[] = "DuckMount";

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, kLogTag, __VA_ARGS__)

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, kLogTag, __VA_ARGS__)

    struct MountEntry {
        std::string source;
        std::string target;
        std::string fsType;
        std::string options;
    };

    struct MountInfoEntry {
        int id = 0;
        int parentId = 0;
        unsigned int major = 0;
        unsigned int minor = 0;
        std::string root;
        std::string target;
        std::string options;
        std::vector<std::string> optionalFields;
        std::string fsType;
        std::string source;
        std::string superOptions;
    };

    enum class AccessResult {
        Exists,
        NotExists,
        PermissionDenied,
    };

#ifdef __NR_statx
    enum class StatxAvailability : int {
        Unknown = 0,
        Supported = 1,
        Unsupported = 2,
    };

    constexpr unsigned int kStatxMountIdMask = 0x00001000;
    constexpr unsigned int kStatxMountRootMask = 0x00002000;
    inline std::atomic<int> g_statxAvailability{
            static_cast<int>(StatxAvailability::Unknown)};
#endif

#ifdef __NR_statx

    inline bool is_statx_supported() {
        const auto cached = static_cast<StatxAvailability>(
                g_statxAvailability.load(std::memory_order_acquire));
        if (cached != StatxAvailability::Unknown) {
            return cached == StatxAvailability::Supported;
        }

        StatxAvailability resolved = StatxAvailability::Unsupported;
        const pid_t pid = fork();
        if (pid < 0) {
            LOGI("statx support probe fork failed: %s", strerror(errno));
        } else if (pid == 0) {
            if (!common::install_seccomp_trap_exit()) {
                _exit(1);
            }
            struct statx stx{};
            errno = 0;
            const long result = syscall(
                    __NR_statx,
                    AT_FDCWD,
                    "/",
                    AT_NO_AUTOMOUNT,
                    STATX_BASIC_STATS,
                    &stx);
            if (result == 0) {
                _exit(0);
            }
            _exit(errno == ENOSYS ? 1 : 0);
        } else {
            int status = 0;
            if (waitpid(pid, &status, 0) < 0) {
                LOGI("statx support probe waitpid failed: %s", strerror(errno));
            } else if (common::seccomp_trapped(status)) {
                LOGI("statx support probe blocked by seccomp; disabling statx probes");
            } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                resolved = StatxAvailability::Supported;
            } else {
                LOGI("statx support probe reported unsupported or inconclusive status=%d",
                     status);
            }
        }

        g_statxAvailability.store(
                static_cast<int>(resolved),
                std::memory_order_release);
        return resolved == StatxAvailability::Supported;
    }

#endif

    int syscall_open_readonly(const char *path, int flags = O_RDONLY | O_CLOEXEC);

    ssize_t syscall_read_fd(int fd, void *buffer, size_t count);

    int syscall_close_fd(int fd);

    int syscall_stat_path(const char *path, struct stat *st);

    ssize_t syscall_readlink_path(const char *path, char *buffer, size_t bufferSize);

    std::string trim_copy(std::string value);

    std::string lowercase_copy(std::string value);

    std::string sanitize_field(std::string value);

    bool contains_ignore_case(const std::string &haystack, const std::string &needle);

    std::string read_file_direct(const char *path, size_t maxSize, bool *readable = nullptr);

    std::string read_namespace_link(const char *path, bool *readable = nullptr);

    AccessResult check_access(
            const char *path,
            bool expectDirectory,
            MountSnapshot &snapshot
    );

    std::vector<MountEntry> parse_mounts(const std::string &raw);

    bool parse_mount_info_line(const std::string &line, MountInfoEntry &entry);

    std::vector<MountInfoEntry> parse_mount_info(const std::string &raw, bool *complete = nullptr);

    void add_finding(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe,
            const std::string &group,
            const std::string &severity,
            const std::string &label,
            const std::string &value,
            const std::string &detail
    );

    bool is_system_partition(const std::string &path);

    bool starts_with(const std::string &value, const std::string &prefix);

    std::string join_optional_fields(const std::vector<std::string> &fields);

    void detect_busybox(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    );

    void detect_root_data_paths(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    );

    void detect_debug_ramdisk(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    );

    void detect_hybrid_paths(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    );

    void detect_maps(
            MountSnapshot &snapshot,
            const std::string &mapsRaw,
            std::unordered_set<std::string> &dedupe
    );

    void detect_mounts(
            MountSnapshot &snapshot,
            const std::vector<MountEntry> &mounts,
            std::unordered_set<std::string> &dedupe
    );

    void detect_mountinfo(
            MountSnapshot &snapshot,
            const std::vector<MountInfoEntry> &entries,
            std::unordered_set<std::string> &dedupe
    );

    void detect_namespace(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    );

    void detect_filesystems(
            MountSnapshot &snapshot,
            const std::vector<MountEntry> &mounts,
            std::unordered_set<std::string> &dedupe
    );

    void detect_inconsistent_mount(
            MountSnapshot &snapshot,
            const std::vector<MountEntry> &mounts,
            std::unordered_set<std::string> &dedupe
    );

}  // namespace duckdetector::mount::detail
