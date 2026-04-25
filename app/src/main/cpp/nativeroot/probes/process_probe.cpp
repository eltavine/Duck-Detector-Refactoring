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

#include "nativeroot/probes/process_probe.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <set>
#include <string>

#include <dirent.h>
#include <fcntl.h>

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

        struct ProcessRule {
            const char *token;
            const char *label;
            bool kernel_su;
            bool apatch;
            bool magisk;
        };

        constexpr ProcessRule kProcessRules[] = {
                {"ksud",     "KernelSU process",    true,  false, false},
                {"kernelsu", "KernelSU process",    true,  false, false},
                {"apd",      "APatch process",      false, true,  false},
                {"apatch",   "APatch process",      false, true,  false},
                {"kpatch",   "KernelPatch process", false, true,  false},
                {"magiskd",  "Magisk process",      false, false, true},
        };

        std::string read_process_label(const char *pid_name) {
            char cmdline_path[256];
            std::snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", pid_name);
            std::string label = read_text_file(cmdline_path, 256);
            if (!label.empty()) {
                return label;
            }

            char comm_path[256];
            std::snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", pid_name);
            return read_text_file(comm_path, 128);
        }

        std::string process_name_for_match(const std::string &label) {
            const std::string lowered = lowercase_copy(label);
            const size_t slash = lowered.rfind('/');
            if (slash == std::string::npos) {
                return lowered;
            }
            return lowered.substr(slash + 1);
        }

        bool matches_process_rule(const std::string &label, const ProcessRule &rule) {
            const std::string candidate = process_name_for_match(label);
            return candidate == rule.token;
        }

    }  // namespace

    ProbeResult run_process_probe() {
        ProbeResult result;
        std::set<std::string> dedupe;

        const int proc_fd = syscall_openat_readonly("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (proc_fd < 0) {
            return result;
        }

        char dent_buffer[4096];
        while (true) {
            const int bytes_read = syscall_getdents64_fd(proc_fd, dent_buffer, sizeof(dent_buffer));
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

                const size_t max_name_length = entry->d_reclen - offsetof(linux_dirent64, d_name);
                const bool process_dir = (entry->d_type == DT_DIR || entry->d_type == DT_UNKNOWN) &&
                                         is_numeric_name(entry->d_name, max_name_length);
                if (process_dir) {
                    const std::string label = read_process_label(entry->d_name);
                    if (!label.empty()) {
                        result.checked_count += 1;
                        for (const ProcessRule &rule: kProcessRules) {
                            if (!matches_process_rule(label, rule)) {
                                continue;
                            }
                            const std::string dedupe_key =
                                    std::string(entry->d_name) + ":" + rule.label;
                            if (!dedupe.insert(dedupe_key).second) {
                                continue;
                            }
                            result.flags.kernel_su = result.flags.kernel_su || rule.kernel_su;
                            result.flags.apatch = result.flags.apatch || rule.apatch;
                            result.flags.magisk = result.flags.magisk || rule.magisk;
                            result.hit_count += 1;
                            result.findings.push_back(
                                    Finding{
                                            .group = "PROCESS",
                                            .label = rule.label,
                                            .value = entry->d_name,
                                            .detail = "PID " + std::string(entry->d_name) + ": " +
                                                      label,
                                            .severity = Severity::kDanger,
                                    }
                            );
                        }
                    } else {
                        result.denied_count += 1;
                    }
                }

                offset += entry->d_reclen;
            }
        }

        syscall_close_fd(proc_fd);
        return result;
    }

}  // namespace duckdetector::nativeroot
