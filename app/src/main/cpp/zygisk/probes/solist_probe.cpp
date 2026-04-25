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

#include "zygisk/probes/solist_probe.h"

#include <link.h>
#include <set>
#include <sstream>

namespace duckdetector::zygisk {

namespace {

struct SoListScanState {
    int callback_index = 0;
    int empty_path_count = 0;
    std::set<std::string> named_libraries;
};

std::string normalize_library_path(std::string path) {
    constexpr std::string_view kDeletedSuffix = " (deleted)";
    if (path.size() > kDeletedSuffix.size() &&
        path.compare(path.size() - kDeletedSuffix.size(), kDeletedSuffix.size(), kDeletedSuffix) == 0) {
        path.erase(path.size() - kDeletedSuffix.size());
    }
    return path;
}

}  // namespace

ProbeResult collect_solist_probe() {
    ProbeResult result;
    SoListScanState state;
    dl_iterate_phdr(
        [](dl_phdr_info* info, size_t, void* user_data) -> int {
            auto* state = reinterpret_cast<SoListScanState*>(user_data);
            if (state == nullptr) {
                return 0;
            }
            const std::string name = info->dlpi_name == nullptr ? std::string() : std::string(info->dlpi_name);
            if (state->callback_index > 0 && name.empty()) {
                state->empty_path_count += 1;
            }
            if (!name.empty() && name.find(".so") != std::string::npos) {
                state->named_libraries.insert(normalize_library_path(name));
            }
            state->callback_index += 1;
            return 0;
        },
        &state
    );

    const auto maps = read_proc_maps();
    std::set<std::string> mapped_shared_objects;
    for (const auto& entry : maps) {
        if (entry.path.find(".so") != std::string::npos && entry.executable()) {
            mapped_shared_objects.insert(normalize_library_path(entry.path));
        }
    }

    if (state.empty_path_count > 0) {
        result.traces.push_back({
            SignalGroup::kLinker,
            SignalSeverity::kWarning,
            "SoList empty-path drift",
            "dl_iterate_phdr exposed " + std::to_string(state.empty_path_count) +
                " additional shared-object entries with empty names.",
        });
    }

    const int mapped_count = static_cast<int>(mapped_shared_objects.size());
    const int named_count = static_cast<int>(state.named_libraries.size());
    if (mapped_count > named_count + 3) {
        std::ostringstream detail;
        detail << "Executable maps expose " << mapped_count
               << " unique shared-object paths while dl_iterate_phdr only reported "
               << named_count << " named libraries.";
        result.traces.push_back({
            SignalGroup::kLinker,
            SignalSeverity::kWarning,
            "Module visibility drift",
            detail.str(),
        });
    }

    result.hit_count = static_cast<int>(result.traces.size());
    result.heuristic_hits = result.hit_count > 0 ? 1 : 0;
    return result;
}

}  // namespace duckdetector::zygisk
