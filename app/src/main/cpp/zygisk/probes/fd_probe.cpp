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

#include "zygisk/probes/fd_probe.h"

#include <array>
#include <dirent.h>
#include <sstream>
#include <unistd.h>

namespace duckdetector::zygisk {

    ProbeResult collect_fd_probe() {
        ProbeResult result;
        DIR *directory = opendir("/proc/self/fd");
        if (directory == nullptr) {
            result.available = false;
            return result;
        }

        std::vector<std::string> suspicious_targets;
        while (const auto *entry = readdir(directory)) {
            if (entry->d_name[0] == '.') {
                continue;
            }

            char proc_path[96] = {};
            std::snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%s", entry->d_name);
            std::array<char, 512> target{};
            const auto length = readlink(proc_path, target.data(), target.size() - 1);
            if (length <= 0) {
                continue;
            }
            target[static_cast<size_t>(length)] = '\0';
            const std::string path(target.data());
            const auto lower = lowercase_copy(path);
            const bool is_deleted_so = lower.find("(deleted)") != std::string::npos &&
                                       lower.find(".so") != std::string::npos;
            const bool is_legitimate_temp = lower.find("/cache/") != std::string::npos ||
                                            lower.find("/tmp/") != std::string::npos ||
                                            lower.find(".tmp") != std::string::npos;

            if ((is_restricted_runtime_path(lower) || is_suspicious_loader_keyword(lower) ||
                 is_deleted_so) && !is_legitimate_temp) {
                suspicious_targets.push_back(path);
            }
        }
        closedir(directory);

        if (!suspicious_targets.empty()) {
            std::ostringstream detail;
            detail << "Open descriptor targets include ";
            for (size_t index = 0; index < suspicious_targets.size() && index < 3U; ++index) {
                if (index > 0U) {
                    detail << ", ";
                }
                detail << suspicious_targets[index];
            }
            if (suspicious_targets.size() > 3U) {
                detail << " and " << (suspicious_targets.size() - 3U) << " more";
            }
            detail << '.';
            result.traces.push_back({
                                            SignalGroup::kFd,
                                            SignalSeverity::kWarning,
                                            "Suspicious fd target",
                                            detail.str(),
                                    });
            result.hit_count = static_cast<int>(suspicious_targets.size());
            result.heuristic_hits = 1;
        }

        return result;
    }

}  // namespace duckdetector::zygisk
