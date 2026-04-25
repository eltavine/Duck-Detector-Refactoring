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

#include "zygisk/probes/vmap_probe.h"

#include <set>
#include <sstream>

namespace duckdetector::zygisk {

    ProbeResult collect_vmap_probe() {
        ProbeResult result;
        const auto maps = read_proc_maps();
        if (maps.empty()) {
            result.available = false;
            return result;
        }

        std::set<unsigned long> jit_cache_inodes;
        std::vector<std::string> suspicious_paths;
        for (const auto &entry: maps) {
            const auto lower = lowercase_copy(entry.path);
            if (entry.executable() &&
                (is_suspicious_loader_keyword(lower) || is_restricted_runtime_path(lower))) {
                suspicious_paths.push_back(entry.path);
            }
            if (entry.executable() &&
                entry.path.find("(deleted)") != std::string::npos &&
                (entry.path.find(".so") != std::string::npos ||
                 is_restricted_runtime_path(lower))) {
                suspicious_paths.push_back(entry.path);
            }
            if (entry.executable() && lower.find("jit-cache") != std::string::npos &&
                entry.inode != 0U) {
                jit_cache_inodes.insert(entry.inode);
            }
            if (entry.executable() && lower.find("framework.jar") != std::string::npos) {
                suspicious_paths.push_back(entry.path);
            }
        }

        if (jit_cache_inodes.size() > 1U) {
            std::ostringstream detail;
            detail << "Executable jit-cache mappings exposed " << jit_cache_inodes.size()
                   << " distinct inodes, which is unusual for a single app process.";
            result.traces.push_back({
                                            SignalGroup::kMaps,
                                            SignalSeverity::kWarning,
                                            "JIT cache drift",
                                            detail.str(),
                                    });
        }

        if (!suspicious_paths.empty()) {
            std::ostringstream detail;
            detail << "Suspicious executable maps include ";
            for (size_t index = 0; index < suspicious_paths.size() && index < 3U; ++index) {
                if (index > 0U) {
                    detail << ", ";
                }
                detail << suspicious_paths[index];
            }
            if (suspicious_paths.size() > 3U) {
                detail << " and " << (suspicious_paths.size() - 3U) << " more";
            }
            detail << '.';
            result.traces.push_back({
                                            SignalGroup::kMaps,
                                            SignalSeverity::kWarning,
                                            "Executable map drift",
                                            detail.str(),
                                    });
        }

        result.hit_count = static_cast<int>(result.traces.size());
        result.heuristic_hits = result.hit_count > 0 ? 1 : 0;
        return result;
    }

}  // namespace duckdetector::zygisk
