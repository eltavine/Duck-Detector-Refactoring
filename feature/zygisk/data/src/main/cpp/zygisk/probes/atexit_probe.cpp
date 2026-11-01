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

#include "zygisk/probes/atexit_probe.h"
#include "zygisk/probes/atexit/table.h"

#include <dlfcn.h>
#include <sys/prctl.h>

namespace duckdetector::zygisk {

    namespace {
        std::vector<MapEntry> unchanged_maps(const std::vector<MapEntry> &before,
                                             const std::vector<MapEntry> &after) {
            std::vector<MapEntry> stable;
            for (const auto &map : before) {
                const auto match = std::find_if(after.begin(), after.end(), [&](const MapEntry &other) {
                    return map.start == other.start && map.end == other.end && map.perms == other.perms &&
                           map.offset == other.offset && map.inode == other.inode &&
                           map.device_major == other.device_major && map.device_minor == other.device_minor &&
                           map.path == other.path;
                });
                if (match != after.end()) stable.push_back(map);
            }
            return stable;
        }
    }

    AtexitProbeResult collect_atexit_probe() {
        AtexitProbeResult output;
        output.table.dumpable = prctl(PR_GET_DUMPABLE);
        auto &result = output.signals;
        const auto maps = read_proc_maps();
        if (maps.empty()) {
            result.available = false;
            output.table.state = AtexitTableState::kUnavailable;
            output.table.detail = "This process's memory map could not be read.";
            return output;
        }

        void *cxa_atexit = dlsym(RTLD_DEFAULT, "__cxa_atexit");
        void *cxa_finalize = dlsym(RTLD_DEFAULT, "__cxa_finalize");
        const auto *atexit_owner = find_map_for_address(maps,
                                                        reinterpret_cast<uintptr_t>(cxa_atexit));
        const auto *finalize_owner = find_map_for_address(maps,
                                                          reinterpret_cast<uintptr_t>(cxa_finalize));

        const bool atexit_drift =
                atexit_owner != nullptr && atexit_owner->path.find("libc.so") == std::string::npos;
        const bool finalize_drift = finalize_owner != nullptr &&
                                    finalize_owner->path.find("libc.so") == std::string::npos;
        if (atexit_drift || finalize_drift) {
            std::string detail = "__cxa_atexit owner=" +
                                 std::string(atexit_owner != nullptr ? atexit_owner->path
                                                                     : "<unknown>") +
                                 ", __cxa_finalize owner=" +
                                 std::string(finalize_owner != nullptr ? finalize_owner->path
                                                                       : "<unknown>") + '.';
            result.traces.push_back({
                                            SignalGroup::kLinker,
                                            SignalSeverity::kWarning,
                                            "Atexit runtime drift",
                                            detail,
                                    });
            result.hit_count = 1;
            result.heuristic_families.insert(HeuristicFamily::kAtexit);
        }

        const auto table = atexit::read_table(maps);
        output.table.state = table.state;
        output.table.detail = table.detail;
        output.table.entries = table.entries.size();
        if (table.state == AtexitTableState::kCollected) {
            // dlclose can unmap an owner after releasing the atexit lock. Changed owners are unknown.
            const auto evidence = atexit::interpret_table(table.entries, unchanged_maps(maps, read_proc_maps()));
            output.table.null_entries = evidence.null_entries;
            output.table.anchored_gaps = evidence.anchored_gaps;
            output.table.anonymous_callbacks = evidence.anonymous_callbacks;
            if (!evidence.bounded || evidence.dense_clearing || evidence.unresolved_callbacks > 0) {
                output.table.state = AtexitTableState::kPartial;
                if (!evidence.bounded) output.table.detail += " No stable application-registration boundary was found.";
                if (evidence.dense_clearing) output.table.detail += " At least 60% of entries were cleared; live ordering context is insufficient.";
                if (evidence.unresolved_callbacks > 0) output.table.detail += " Some callback owners could not be resolved in stable executable mappings.";
            }
            result.traces.insert(result.traces.end(), evidence.traces.begin(), evidence.traces.end());
            const size_t hits = evidence.anchored_gaps + evidence.anonymous_callbacks;
            if (hits != 0) {
                result.hit_count += static_cast<int>(hits);
                result.heuristic_families.insert(HeuristicFamily::kAtexit);
            }
        }
        return output;
    }

}  // namespace duckdetector::zygisk
