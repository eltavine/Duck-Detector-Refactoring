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

#include "memory/detectors/linker_detector.h"

#include "memory/common/maps_reader.h"

#include <link.h>

#include <cstdint>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace duckdetector::memory {
    namespace {

        struct LinkerObject {
            std::string name;
            std::vector<std::pair<std::uintptr_t, std::uintptr_t>> load_ranges;
        };

        struct IterateState {
            std::set<std::string> *libs = nullptr;
            std::vector<LinkerObject> *objects = nullptr;
        };

        bool is_normal_apk_library_path(const std::string &lowered);

        bool is_shared_object_path(const std::string &lowered);

        bool is_linker_candidate(const std::string &path) {
            if (path.empty()) {
                return false;
            }
            const std::string lowered = to_lower_ascii(path);
            if (is_benign_loader_artifact_path(lowered)) {
                return false;
            }
            return is_shared_object_path(lowered) || is_suspicious_loader_path(lowered);
        }

        std::string normalize_library_name(std::string value) {
            const size_t deleted_pos = value.find(" (deleted)");
            if (deleted_pos != std::string::npos) {
                value.erase(deleted_pos);
            }
            return value;
        }

        bool is_runtime_artifact_path(const std::string &lowered) {
            return lowered.find(".oat") != std::string::npos ||
                   lowered.find(".odex") != std::string::npos ||
                   lowered.find(".vdex") != std::string::npos;
        }

        bool is_app_package_path(const std::string &lowered) {
            return lowered.rfind("/data/app/", 0) == 0 ||
                   lowered.rfind("/mnt/expand/", 0) == 0;
        }

        bool is_normal_apk_library_path(const std::string &lowered) {

            if (lowered.find(".apk!/lib/") != std::string::npos) {
                return lowered.find(".so") != std::string::npos;
            }
            if (!is_app_package_path(lowered) || lowered.find(".so") == std::string::npos) {
                return false;
            }
            return lowered.find("/lib/") != std::string::npos ||
                   lowered.find("/lib64/") != std::string::npos;
        }

        bool is_shared_object_path(const std::string &lowered) {
            return lowered.find(".so") != std::string::npos ||
                   is_normal_apk_library_path(lowered);
        }

        bool should_compare_map_entry(const MapEntry &entry) {
            if (entry.path.empty()) {
                return false;
            }
            const std::string lowered = to_lower_ascii(entry.path);
            if (is_benign_loader_artifact_path(lowered)) {
                return false;
            }
            if (is_suspicious_loader_path(lowered)) {
                return true;
            }
            if (!entry.executable) {
                return false;
            }
            return is_shared_object_path(lowered);
        }

        bool is_deleted_library_candidate(const MapEntry &entry) {
            if (entry.path.find("(deleted)") == std::string::npos) {
                return false;
            }
            const std::string lowered = to_lower_ascii(entry.path);
            if (is_benign_loader_artifact_path(lowered)) {
                return false;
            }
            return is_shared_object_path(lowered) || is_suspicious_loader_path(lowered);
        }

        bool path_matches(
                const std::string &lhs,
                const std::string &rhs
        ) {
            if (lhs == rhs) {
                return true;
            }
            if (normalize_library_name(lhs) == normalize_library_name(rhs)) {
                return true;
            }
            return basename_of(normalize_library_name(lhs)) ==
                   basename_of(normalize_library_name(rhs));
        }

        bool range_overlaps(
                const std::uintptr_t start,
                const std::uintptr_t end,
                const MapEntry &entry
        ) {
            return start < entry.end && end > entry.start;
        }

        bool is_object_covered_in_maps(
                const LinkerObject &object,
                const std::vector<MapEntry> &maps
        ) {
            if (object.load_ranges.empty()) {
                return true;
            }
            for (const auto &[start, end]: object.load_ranges) {
                bool covered = false;
                for (const MapEntry &entry: maps) {
                    if (range_overlaps(start, end, entry)) {
                        covered = true;
                        break;
                    }
                }
                if (!covered) {
                    return false;
                }
            }
            return true;
        }

    }  // namespace

    LinkerSignals detect_linker_anomalies(const std::vector<MapEntry> &maps) {
        LinkerSignals signals;
        std::set<std::string> map_libs;
        std::set<std::string> deleted_reported;
        for (const MapEntry &entry: maps) {
            if (!should_compare_map_entry(entry)) {
                continue;
            }
            map_libs.insert(entry.path);
            if (is_deleted_library_candidate(entry)) {
                const std::string dedupe_key = normalize_library_name(entry.path);
                if (deleted_reported.insert(dedupe_key).second) {
                    signals.deleted_library = true;
                    signals.findings.push_back(
                            Finding{
                                    .section = "LINKER",
                                    .category = "LINKER",
                                    .label = "Deleted mapped library",
                                    .detail = entry.path,
                                    .severity = FindingSeverity::kHigh,
                            }
                    );
                }
            }
        }

        std::set<std::string> linker_libs;
        std::vector<LinkerObject> linker_objects;
        IterateState iterate_state{
                .libs = &linker_libs,
                .objects = &linker_objects,
        };
        dl_iterate_phdr(
                [](dl_phdr_info *info, size_t, void *data) -> int {
                    auto *state = static_cast<IterateState *>(data);
                    if (info->dlpi_name != nullptr && info->dlpi_name[0] != '\0') {
                        state->libs->insert(info->dlpi_name);
                        LinkerObject object;
                        object.name = info->dlpi_name;
                        for (ElfW(Half) index = 0; index < info->dlpi_phnum; ++index) {
                            const ElfW(Phdr) &phdr = info->dlpi_phdr[index];
                            if (phdr.p_type != PT_LOAD || phdr.p_memsz == 0) {
                                continue;
                            }
                            const auto start = static_cast<std::uintptr_t>(info->dlpi_addr +
                                                                           phdr.p_vaddr);
                            const auto end = start + static_cast<std::uintptr_t>(phdr.p_memsz);
                            if (end > start) {
                                object.load_ranges.emplace_back(start, end);
                            }
                        }
                        state->objects->push_back(std::move(object));
                    }
                    return 0;
                },
                &iterate_state
        );

        for (const std::string &map_lib: map_libs) {
            if (is_benign_loader_artifact_path(map_lib)) {
                continue;
            }
            bool found = false;
            for (const std::string &linker_lib: linker_libs) {
                if (path_matches(map_lib, linker_lib)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                signals.maps_only_module = true;
                std::ostringstream detail;
                detail << "Mapped candidate not reported by dl_iterate_phdr: " << map_lib;
                signals.findings.push_back(
                        Finding{
                                .section = "LINKER",
                                .category = "LINKER",
                                .label = "Maps-only module",
                                .detail = detail.str(),
                                .severity = FindingSeverity::kMedium,
                        }
                );
            }
        }

        std::set<std::string> hidden_reported;
        for (const LinkerObject &linker_object: linker_objects) {
            const std::string &linker_lib = linker_object.name;
            if (!is_linker_candidate(linker_lib)) {
                continue;
            }
            const std::string lowered = to_lower_ascii(linker_lib);
            bool found = false;
            for (const std::string &map_lib: map_libs) {
                if (path_matches(linker_lib, map_lib)) {
                    found = true;
                    break;
                }
            }
            if (found) {
                continue;
            }

            const bool covered_in_maps = is_object_covered_in_maps(linker_object, maps);
            const bool suspicious_path = is_suspicious_loader_path(lowered);
            if (covered_in_maps &&
                !suspicious_path) {
                continue;
            }
            if (covered_in_maps &&
                (is_system_path(lowered) || is_normal_apk_library_path(lowered) ||
                 is_runtime_artifact_path(lowered))) {
                continue;
            }
            if (!covered_in_maps &&
                (is_system_path(lowered) || is_normal_apk_library_path(lowered) ||
                 is_runtime_artifact_path(lowered)) &&
                !suspicious_path) {
                continue;
            }
            if (hidden_reported.insert(linker_lib).second) {
                signals.hidden_module = true;
                std::ostringstream detail;
                detail << "dl_iterate_phdr reports suspicious library missing from maps: "
                       << linker_lib;
                signals.findings.push_back(
                        Finding{
                                .section = "LINKER",
                                .category = "LINKER",
                                .label = "Hidden loader entry",
                                .detail = detail.str(),
                                .severity = FindingSeverity::kHigh,
                        }
                );
            }
        }

        return signals;
    }

}  // namespace duckdetector::memory
