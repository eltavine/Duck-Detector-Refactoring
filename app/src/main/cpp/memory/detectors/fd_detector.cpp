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

#include "memory/detectors/fd_detector.h"

#include "memory/common/maps_reader.h"

#include <dirent.h>
#include <unistd.h>

#include <cstring>
#include <set>
#include <sstream>

namespace duckdetector::memory {
    namespace {

        Finding make_fd_finding(
                const char *label,
                const FindingSeverity severity,
                const std::string &detail
        ) {
            return Finding{
                    .section = "FD",
                    .category = "FD",
                    .label = label,
                    .detail = detail,
                    .severity = severity,
            };
        }

        std::string read_link_target(const std::string &path) {
            char buffer[1024];
            const ssize_t length = ::readlink(path.c_str(), buffer, sizeof(buffer) - 1);
            if (length <= 0) {
                return {};
            }
            buffer[length] = '\0';
            return std::string(buffer);
        }

        bool is_benign_deleted_runtime_target(const std::string &lowered_path) {
            return is_benign_loader_artifact_path(lowered_path);
        }

        bool is_benign_exec_ashmem_path(const std::string &lowered_path) {
            return is_probably_jit_path(lowered_path) ||
                   lowered_path.find("fontmap") != std::string::npos ||
                   lowered_path.find("gfxstats-") != std::string::npos ||
                   lowered_path.find("gralloc") != std::string::npos ||
                   lowered_path.find("hwui") != std::string::npos ||
                   lowered_path.find("skia") != std::string::npos ||
                   lowered_path.find("fresco") != std::string::npos;
        }

    }  // namespace

    FdSignals detect_fd_anomalies(const std::vector<MapEntry> &maps) {
        FdSignals signals;
        std::set<std::string> dedupe;

        for (const MapEntry &entry: maps) {
            if (!entry.executable || is_probably_jit_path(entry.path)) {
                continue;
            }
            const std::string lowered = to_lower_ascii(entry.path);
            if (lowered.rfind("/dev/ashmem", 0) == 0 &&
                !is_benign_exec_ashmem_path(lowered)) {
                signals.exec_ashmem = true;
                if (dedupe.insert(entry.path).second) {
                    signals.findings.push_back(
                            make_fd_finding("Executable ashmem mapping", FindingSeverity::kHigh,
                                            entry.path)
                    );
                }
            }
            if (lowered.rfind("/dev/zero", 0) == 0) {
                signals.dev_zero_exec = true;
                if (dedupe.insert(entry.path).second) {
                    signals.findings.push_back(
                            make_fd_finding("Executable /dev/zero mapping", FindingSeverity::kHigh,
                                            entry.path)
                    );
                }
            }
            if (lowered.find("memfd:") != std::string::npos &&
                !is_benign_loader_artifact_path(lowered) &&
                is_suspicious_loader_path(lowered)) {
                signals.suspicious_memfd = true;
                if (dedupe.insert(entry.path).second) {
                    signals.findings.push_back(
                            make_fd_finding("Suspicious executable memfd",
                                            FindingSeverity::kCritical, entry.path)
                    );
                }
            }
            if (lowered.find("(deleted)") != std::string::npos &&
                !is_benign_deleted_runtime_target(lowered) &&
                (is_suspicious_loader_path(lowered) || lowered.find(".so") != std::string::npos)) {
                signals.deleted_so = true;
                if (dedupe.insert(entry.path).second) {
                    signals.findings.push_back(
                            make_fd_finding("Deleted executable library", FindingSeverity::kHigh,
                                            entry.path)
                    );
                }
            }
        }

        DIR *dir = ::opendir("/proc/self/fd");
        if (dir == nullptr) {
            return signals;
        }
        while (dirent *entry = ::readdir(dir)) {
            if (entry->d_name[0] == '.') {
                continue;
            }
            const std::string fd_path = std::string("/proc/self/fd/") + entry->d_name;
            const std::string target = read_link_target(fd_path);
            if (target.empty()) {
                continue;
            }
            const std::string lowered = to_lower_ascii(target);
            if (lowered.find("memfd:") != std::string::npos &&
                !is_benign_loader_artifact_path(lowered) &&
                is_suspicious_loader_path(lowered)) {
                signals.suspicious_memfd = true;
                if (dedupe.insert(target).second) {
                    std::ostringstream detail;
                    detail << "fd " << entry->d_name << " -> " << target;
                    signals.findings.push_back(
                            make_fd_finding("Suspicious memfd handle", FindingSeverity::kCritical,
                                            detail.str())
                    );
                }
            }
            if (lowered.find("(deleted)") != std::string::npos &&
                !is_benign_deleted_runtime_target(lowered) &&
                (is_suspicious_loader_path(lowered) || lowered.find(".so") != std::string::npos)) {
                signals.deleted_so = true;
                if (dedupe.insert(target).second) {
                    std::ostringstream detail;
                    detail << "fd " << entry->d_name << " -> " << target;
                    signals.findings.push_back(
                            make_fd_finding("Deleted shared object handle", FindingSeverity::kHigh,
                                            detail.str())
                    );
                }
            }
        }
        ::closedir(dir);

        return signals;
    }

}  // namespace duckdetector::memory
