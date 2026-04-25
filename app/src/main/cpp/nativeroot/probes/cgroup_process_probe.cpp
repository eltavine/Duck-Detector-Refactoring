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

#include "nativeroot/probes/cgroup_process_probe.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <set>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "nativeroot/common/io_utils.h"

namespace duckdetector::nativeroot {
    namespace {

        struct linux_dirent64 {
            std::uint64_t d_ino;
            std::int64_t d_off;
            unsigned short d_reclen;
            unsigned char d_type;
            char d_name[];
        };

        constexpr const char *kUidRootPaths[] = {
                "/sys/fs/cgroup",
                "/sys/fs/cgroup/apps",
                "/sys/fs/cgroup/system",
                "/dev/cg2_bpf",
                "/dev/cg2_bpf/apps",
                "/dev/cg2_bpf/system",
                "/acct",
                "/dev/memcg/apps",
        };

        constexpr const char *kFallbackUidPathPatterns[] = {
                "/sys/fs/cgroup/uid_%d",
                "/sys/fs/cgroup/apps/uid_%d",
                "/sys/fs/cgroup/system/uid_%d",
                "/dev/cg2_bpf/uid_%d",
                "/dev/cg2_bpf/apps/uid_%d",
                "/dev/cg2_bpf/system/uid_%d",
                "/acct/uid_%d",
                "/dev/memcg/apps/uid_%d",
        };

        int parse_pid_dir(const char *name, const size_t max_length) {
            constexpr char kPrefix[] = "pid_";
            if (name == nullptr) {
                return -1;
            }
            if (std::strncmp(name, kPrefix, sizeof(kPrefix) - 1) != 0) {
                return -1;
            }

            const char *pid_chars = name + sizeof(kPrefix) - 1;
            if (*pid_chars == '\0') {
                return -1;
            }
            if (!is_numeric_name(pid_chars,
                                 max_length >= sizeof(kPrefix) ? max_length - (sizeof(kPrefix) - 1)
                                                               : 0)) {
                return -1;
            }
            return std::atoi(pid_chars);
        }

        int parse_uid_dir(const char *name, const size_t max_length) {
            constexpr char kPrefix[] = "uid_";
            if (name == nullptr) {
                return -1;
            }
            if (std::strncmp(name, kPrefix, sizeof(kPrefix) - 1) != 0) {
                return -1;
            }

            const char *uid_chars = name + sizeof(kPrefix) - 1;
            if (*uid_chars == '\0') {
                return -1;
            }
            if (!is_numeric_name(uid_chars,
                                 max_length >= sizeof(kPrefix) ? max_length - (sizeof(kPrefix) - 1)
                                                               : 0)) {
                return -1;
            }
            return std::atoi(uid_chars);
        }

        std::string read_bytes_file(const char *path, const size_t max_size) {
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
            return content;
        }

        int parse_status_uid(const std::string &status_text) {
            if (status_text.empty()) {
                return -1;
            }

            const std::string key = "\nUid:";
            const size_t key_pos = status_text.find(key);
            const size_t start = key_pos == std::string::npos ? 0 : key_pos + 1;
            const size_t line_end = status_text.find('\n', start);
            const std::string line = trim_copy(status_text.substr(start, line_end - start));
            if (line.rfind("Uid:", 0) != 0) {
                return -1;
            }
            const std::string ids = trim_copy(line.substr(4));
            const size_t space = ids.find_first_of(" \t");
            return std::atoi(ids.substr(0, space).c_str());
        }

        std::string read_proc_text(int pid, const char *suffix, size_t max_size) {
            char buffer[256];
            std::snprintf(buffer, sizeof(buffer), "/proc/%d/%s", pid, suffix);
            return read_bytes_file(buffer, max_size);
        }

        std::string read_proc_line(int pid, const char *suffix, size_t max_size) {
            return trim_copy(read_proc_text(pid, suffix, max_size));
        }

        long long parse_proc_starttime_ticks(const std::string &stat_text) {
            if (stat_text.empty()) {
                return -1;
            }

            const size_t close_paren = stat_text.rfind(')');
            if (close_paren == std::string::npos || close_paren + 2 >= stat_text.size()) {
                return -1;
            }

            std::istringstream input(stat_text.substr(close_paren + 2));
            std::string token;
            for (int field = 3; field <= 22; ++field) {
                if (!(input >> token)) {
                    return -1;
                }
                if (field == 22) {
                    return std::atoll(token.c_str());
                }
            }
            return -1;
        }

        void append_uid_path(
                const std::string &path,
                int uid,
                std::vector<std::pair<std::string, int>> &paths,
                std::set<std::string> &dedupe
        ) {
            if (!dedupe.insert(path).second) {
                return;
            }
            paths.emplace_back(path, uid);
        }

        void collect_uid_paths_from_root(
                const char *root_path,
                std::vector<std::pair<std::string, int>> &paths,
                std::set<std::string> &dedupe
        ) {
            const int root_fd = syscall_openat_readonly(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (root_fd < 0) {
                return;
            }

            char dent_buffer[4096];
            while (true) {
                const int bytes_read = syscall_getdents64_fd(root_fd, dent_buffer, sizeof(dent_buffer));
                if (bytes_read <= 0) {
                    break;
                }

                int offset = 0;
                while (offset < bytes_read) {
                    if (offset + static_cast<int>(offsetof(linux_dirent64, d_name)) >= bytes_read) {
                        break;
                    }

                    auto *entry = reinterpret_cast<linux_dirent64 *>(dent_buffer + offset);
                    if (entry->d_reclen == 0 || offset + entry->d_reclen > bytes_read) {
                        break;
                    }

                    const size_t max_name_length =
                            entry->d_reclen - offsetof(linux_dirent64, d_name);
                    const bool dir_like = entry->d_type == DT_DIR || entry->d_type == DT_UNKNOWN;
                    const int uid = dir_like ? parse_uid_dir(entry->d_name, max_name_length) : -1;
                    if (uid >= 0) {
                        append_uid_path(
                                std::string(root_path) + "/" + std::string(entry->d_name),
                                uid,
                                paths,
                                dedupe
                        );
                    }

                    offset += entry->d_reclen;
                }
            }

            syscall_close_fd(root_fd);
        }

        std::vector<std::pair<std::string, int>> candidate_uid_paths() {
            std::vector<std::pair<std::string, int>> paths;
            std::set<std::string> dedupe;

            for (const char *root_path: kUidRootPaths) {
                collect_uid_paths_from_root(root_path, paths, dedupe);
            }

            if (!paths.empty()) {
                return paths;
            }

            const std::set<int> fallback_uids = {0, 1000, 2000, static_cast<int>(getuid())};
            for (const int uid: fallback_uids) {
                for (const char *pattern: kFallbackUidPathPatterns) {
                    char buffer[256];
                    std::snprintf(buffer, sizeof(buffer), pattern, uid);
                    append_uid_path(buffer, uid, paths, dedupe);
                }
            }
            return paths;
        }

    }  // namespace

    CgroupLeakSnapshot collect_cgroup_leak_snapshot() {
        CgroupLeakSnapshot snapshot;
        std::set<std::string> dedupe;

        const auto uid_paths = candidate_uid_paths();
        snapshot.path_check_count = static_cast<int>(uid_paths.size());

        for (const auto &[uid_path, uid]: uid_paths) {
            CgroupLeakPathEntry path_entry{
                    .path = uid_path,
                    .uid = uid,
            };

            const int uid_fd = syscall_openat_readonly(uid_path.c_str(),
                                                       O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (uid_fd < 0) {
                snapshot.paths.push_back(path_entry);
                continue;
            }

            snapshot.available = true;
            path_entry.accessible = true;
            snapshot.accessible_path_count += 1;

            char dent_buffer[4096];
            while (true) {
                const int bytes_read = syscall_getdents64_fd(uid_fd, dent_buffer,
                                                             sizeof(dent_buffer));
                if (bytes_read <= 0) {
                    break;
                }

                int offset = 0;
                while (offset < bytes_read) {
                    if (offset + static_cast<int>(offsetof(linux_dirent64, d_name)) >= bytes_read) {
                        break;
                    }

                    auto *entry = reinterpret_cast<linux_dirent64 *>(dent_buffer + offset);
                    if (entry->d_reclen == 0 || offset + entry->d_reclen > bytes_read) {
                        break;
                    }

                    const size_t max_name_length =
                            entry->d_reclen - offsetof(linux_dirent64, d_name);
                    const bool dir_like =
                            entry->d_type == DT_DIR || entry->d_type == DT_UNKNOWN;
                    const int pid = dir_like ? parse_pid_dir(entry->d_name, max_name_length) : -1;
                    if (pid > 0) {
                        path_entry.pid_count += 1;
                        snapshot.process_count += 1;

                        const std::string status_text = read_proc_text(pid, "status", 4096);
                        const std::string stat_text = read_proc_text(pid, "stat", 512);
                        const std::string proc_context = read_proc_line(pid, "attr/current", 256);
                        const std::string comm = read_proc_line(pid, "comm", 256);
                        const std::string cmdline = read_proc_text(pid, "cmdline", 512);
                        const SyscallProbeResult kill_result = probe_kill_zero(pid);
                        const SyscallProbeResult getsid_result = probe_getsid(pid);
                        const SyscallProbeResult getpgid_result = probe_getpgid(pid);
                        const SyscallProbeResult sched_result = probe_sched_getscheduler(pid);
                        const SyscallProbeResult pidfd_result = probe_pidfd_open(pid);
                        if (status_text.empty()) {
                            snapshot.proc_denied_count += 1;
                        }

                        const std::string dedupe_key = uid_path + "|" + std::to_string(pid);
                        if (dedupe.insert(dedupe_key).second) {
                            snapshot.entries.push_back(
                                    CgroupLeakProcessEntry{
                                            .uid_path = uid_path,
                                            .cgroup_uid = uid,
                                            .pid = pid,
                                            .proc_uid = parse_status_uid(status_text),
                                            .starttime_ticks = parse_proc_starttime_ticks(stat_text),
                                            .kill_errno = kill_result.error,
                                            .getsid_value = getsid_result.value >= 0
                                                            ? static_cast<int>(getsid_result.value)
                                                            : -1,
                                            .getsid_errno = getsid_result.error,
                                            .getpgid_value = getpgid_result.value >= 0
                                                             ? static_cast<int>(getpgid_result.value)
                                                             : -1,
                                            .getpgid_errno = getpgid_result.error,
                                            .sched_policy = sched_result.value >= 0
                                                            ? static_cast<int>(sched_result.value)
                                                            : -1,
                                            .sched_errno = sched_result.error,
                                            .pidfd_errno = pidfd_result.error,
                                            .proc_context = proc_context,
                                            .comm = comm,
                                            .cmdline = cmdline,
                                    }
                            );
                        }
                    }

                    offset += entry->d_reclen;
                }
            }

            syscall_close_fd(uid_fd);
            snapshot.paths.push_back(path_entry);
        }

        return snapshot;
    }

}  // namespace duckdetector::nativeroot
