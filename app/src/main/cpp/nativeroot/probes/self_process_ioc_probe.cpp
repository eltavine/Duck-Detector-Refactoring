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

#include "nativeroot/probes/self_process_ioc_probe.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
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

        constexpr const char *kSelfContextPath = "/proc/self/attr/current";
        constexpr const char *kSelfFdPath = "/proc/self/fd";
        constexpr const char *kKernelSuContext = "u:r:su:s0";

    }  // namespace

    ProbeResult run_self_process_ioc_probe() {
        ProbeResult result;

        const std::string context = read_text_file(kSelfContextPath, 256);
        if (!context.empty() && context == kKernelSuContext) {
            result.flags.kernel_su = true;
            result.hit_count += 1;
            result.findings.push_back(
                    Finding{
                            .group = "PROCESS",
                            .label = "Self SELinux context",
                            .value = context,
                            .detail = "The current app process is already running under the KernelSU su domain.",
                            .severity = Severity::kDanger,
                    }
            );
        }

        int driver_fd_count = 0;
        int fdwrapper_count = 0;
        const int proc_fd = syscall_openat_readonly(kSelfFdPath,
                                                    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (proc_fd >= 0) {
            char dent_buffer[2048];
            while (true) {
                const int bytes_read = syscall_getdents64_fd(proc_fd, dent_buffer,
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
                    if ((entry->d_type == DT_LNK || entry->d_type == DT_UNKNOWN) &&
                        is_numeric_name(entry->d_name, max_name_length)) {
                        char link_path[128];
                        std::snprintf(link_path, sizeof(link_path), "%s/%s", kSelfFdPath,
                                      entry->d_name);
                        const std::string target = read_link_target(link_path, 256);
                        if (target.find("[ksu_driver]") != std::string::npos) {
                            driver_fd_count += 1;
                        }
                        if (target.find("[ksu_fdwrapper]") != std::string::npos) {
                            fdwrapper_count += 1;
                        }
                    }

                    offset += entry->d_reclen;
                }
            }
            syscall_close_fd(proc_fd);
        }

        if (driver_fd_count > 0 || fdwrapper_count > 0) {
            result.flags.kernel_su = true;
            result.hit_count += 1;
            result.findings.push_back(
                    Finding{
                            .group = "PROCESS",
                            .label = "Self KSU file descriptors",
                            .value = "driver=" + std::to_string(driver_fd_count) +
                                     " wrapper=" + std::to_string(fdwrapper_count),
                            .detail = "The current app process already holds KernelSU [ksu_driver] or [ksu_fdwrapper] descriptors before privileged escalation.",
                            .severity = Severity::kDanger,
                    }
            );
        }

        if (driver_fd_count == 0 && fdwrapper_count == 0 && result.findings.empty() &&
            !context.empty()) {
            result.findings.push_back(
                    Finding{
                            .group = "PROCESS",
                            .label = "Self SELinux context",
                            .value = context,
                            .detail = "The current app process context stayed outside the KernelSU su domain.",
                            .severity = Severity::kInfo,
                    }
            );
        }

        result.checked_count = 2;
        result.denied_count = 0;
        result.numeric_value = static_cast<long>(driver_fd_count);
        result.extra_numeric_value = static_cast<long>(fdwrapper_count);
        result.aux_flags = context == kKernelSuContext ? 1L : 0L;
        result.extra_text = context;
        return result;
    }

}  // namespace duckdetector::nativeroot
