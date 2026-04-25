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

#ifndef DUCKDETECTOR_NATIVEROOT_COMMON_IO_UTILS_H
#define DUCKDETECTOR_NATIVEROOT_COMMON_IO_UTILS_H

#include <cstddef>
#include <initializer_list>
#include <string>
#include <sys/types.h>

namespace duckdetector::nativeroot {

    struct SyscallProbeResult {
        long value = -1;
        int error = 0;
    };

    int syscall_openat_readonly(const char *path, int flags);

    ssize_t syscall_read_fd(int fd, void *buffer, size_t count);

    int syscall_close_fd(int fd);

    int syscall_getdents64_fd(int fd, void *buffer, size_t count);

    SyscallProbeResult probe_kill_zero(pid_t pid);

    SyscallProbeResult probe_getsid(pid_t pid);

    SyscallProbeResult probe_getpgid(pid_t pid);

    SyscallProbeResult probe_sched_getscheduler(pid_t pid);

    SyscallProbeResult probe_pidfd_open(pid_t pid);

    std::string read_text_file(const char *path, size_t max_size);

    std::string read_link_target(const char *path, size_t max_size);

    bool file_exists(const char *path);

    bool dir_exists(const char *path);

    bool path_exists_no_follow(const char *path);

    bool path_openable(const char *path);

    bool directory_contains_entry(const char *directory_path, const char *entry_name);

    std::string read_property_value(const char *name);

    std::string trim_copy(std::string value);

    std::string lowercase_copy(std::string value);

    bool contains_ignore_case(const std::string &haystack, const char *needle);

    bool contains_any_ignore_case(
            const std::string &haystack,
            std::initializer_list<const char *> needles
    );

    bool is_numeric_name(const char *name, size_t max_length);

}  // namespace duckdetector::nativeroot

#endif  // DUCKDETECTOR_NATIVEROOT_COMMON_IO_UTILS_H
