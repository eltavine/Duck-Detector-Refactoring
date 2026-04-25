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

#include "memory/detectors/maps_anomaly_detector.h"

#include "memory/common/maps_reader.h"

#include <sstream>

namespace duckdetector::memory {
    namespace {

        Finding make_map_finding(
                const char *category,
                const char *label,
                const FindingSeverity severity,
                const std::string &detail
        ) {
            return Finding{
                    .section = "MAPS",
                    .category = category,
                    .label = label,
                    .detail = detail,
                    .severity = severity,
            };
        }

        bool is_relevant_exec_entry(const MapEntry &entry) {
            return entry.executable && !is_benign_art_code_cache_path(entry.path);
        }

    }  // namespace

    MapsSignals detect_maps_anomalies(
            const std::vector<MapEntry> &maps,
            const std::vector<SmapsEntry> &smaps
    ) {
        MapsSignals signals;

        for (const MapEntry &entry: maps) {
            if (!is_relevant_exec_entry(entry)) {
                continue;
            }

            if (entry.writable) {
                signals.writable_exec = true;
                std::ostringstream detail;
                detail << "Writable+executable mapping 0x" << std::hex << entry.start
                       << "-0x" << entry.end << " "
                       << (entry.path.empty() ? "[anonymous]" : entry.path);
                signals.findings.push_back(
                        make_map_finding("TEXT_SECTION", "Writable executable region",
                                         FindingSeverity::kHigh, detail.str())
                );
            }

            if (is_anonymous_path(entry.path)) {
                signals.anonymous_exec = true;
                std::ostringstream detail;
                detail << "Executable anonymous mapping 0x" << std::hex << entry.start
                       << "-0x" << entry.end << " "
                       << (entry.path.empty() ? "[anonymous]" : entry.path);
                signals.findings.push_back(
                        make_map_finding("SMAPS", "Anonymous executable code",
                                         FindingSeverity::kHigh, detail.str())
                );
            }
        }

        for (const SmapsEntry &entry: smaps) {
            if (!is_relevant_exec_entry(entry.map)) {
                continue;
            }

            if (entry.swap_kb > 0) {
                signals.swapped_exec = true;
                std::ostringstream detail;
                detail << entry.map.path << " has " << entry.swap_kb
                       << " kB swapped executable pages";
                signals.findings.push_back(
                        make_map_finding("SMAPS", "Swapped executable pages",
                                         FindingSeverity::kMedium, detail.str())
                );
            }

            if (entry.shared_dirty_kb > 0 && is_system_path(entry.map.path)) {
                signals.shared_dirty_exec = true;
                std::ostringstream detail;
                detail << entry.map.path << " has " << entry.shared_dirty_kb
                       << " kB shared-dirty executable pages";
                signals.findings.push_back(
                        make_map_finding("SMAPS", "Shared-dirty system code",
                                         FindingSeverity::kHigh, detail.str())
                );
            }

            if (entry.anonymous_kb > 0 && is_system_path(entry.map.path)) {
                signals.anonymous_exec = true;
                std::ostringstream detail;
                detail << entry.map.path << " reports " << entry.anonymous_kb
                       << " kB anonymous executable pages";
                signals.findings.push_back(
                        make_map_finding("SMAPS", "Anonymous executable pages on system mapping",
                                         FindingSeverity::kMedium, detail.str())
                );
            }
        }

        return signals;
    }

}  // namespace duckdetector::memory
