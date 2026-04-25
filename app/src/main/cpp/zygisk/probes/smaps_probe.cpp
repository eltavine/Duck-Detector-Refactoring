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

#include "zygisk/probes/smaps_probe.h"

#include <cstdlib>
#include <sstream>

namespace duckdetector::zygisk {

    ProbeResult collect_smaps_probe() {
        ProbeResult result;
        const auto lines = split_lines(read_text_file("/proc/self/smaps"));
        if (lines.empty()) {
            result.available = false;
            return result;
        }

        std::string current_path;
        bool current_exec = false;
        bool current_system = false;
        size_t private_dirty_kb = 0;
        size_t shared_dirty_kb = 0;

        auto finalize_region = [&]() {
            if (!current_exec || !current_system) {
                private_dirty_kb = 0;
                shared_dirty_kb = 0;
                return;
            }
            if (private_dirty_kb + shared_dirty_kb < 8U) {
                private_dirty_kb = 0;
                shared_dirty_kb = 0;
                return;
            }
            std::ostringstream detail;
            detail << current_path << " has " << private_dirty_kb << " kB Private_Dirty and "
                   << shared_dirty_kb << " kB Shared_Dirty on an executable system mapping.";
            result.traces.push_back({
                                            SignalGroup::kMaps,
                                            SignalSeverity::kWarning,
                                            "Dirty system code pages",
                                            detail.str(),
                                    });
            private_dirty_kb = 0;
            shared_dirty_kb = 0;
        };

        for (const auto &line: lines) {
            if (line.find('-') != std::string::npos && line.find(':') == std::string::npos) {
                finalize_region();
                current_path.clear();
                current_exec = false;
                current_system = false;
                unsigned long long start = 0;
                unsigned long long end = 0;
                char perms[5] = {};
                unsigned long long offset = 0;
                char dev[32] = {};
                unsigned long long inode = 0;
                int path_offset = 0;
                const int matched = std::sscanf(
                        line.c_str(),
                        "%llx-%llx %4s %llx %31s %llu %n",
                        &start,
                        &end,
                        perms,
                        &offset,
                        dev,
                        &inode,
                        &path_offset
                );
                if (matched >= 6 && path_offset > 0 &&
                    path_offset < static_cast<int>(line.size())) {
                    current_path = trim_copy(line.substr(static_cast<size_t>(path_offset)));
                    current_exec = std::string(perms).find('x') != std::string::npos;
                    current_system = starts_with(current_path, "/system/") ||
                                     starts_with(current_path, "/vendor/") ||
                                     starts_with(current_path, "/apex/");
                }
                continue;
            }
            if (starts_with(line, "Private_Dirty:")) {
                private_dirty_kb = static_cast<size_t>(std::strtoul(
                        trim_copy(line.substr(14)).c_str(), nullptr, 10));
            } else if (starts_with(line, "Shared_Dirty:")) {
                shared_dirty_kb = static_cast<size_t>(std::strtoul(
                        trim_copy(line.substr(13)).c_str(), nullptr, 10));
            }
        }
        finalize_region();

        result.hit_count = static_cast<int>(result.traces.size());
        result.heuristic_hits = result.hit_count > 0 ? 1 : 0;
        return result;
    }

}  // namespace duckdetector::zygisk
