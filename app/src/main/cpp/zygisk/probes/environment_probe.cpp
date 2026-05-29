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

#include "zygisk/probes/environment_probe.h"

#include <cstdlib>
#include <set>
#include <sstream>

namespace duckdetector::zygisk {

    namespace {

        bool is_zygisk_tmp_path(const std::string &value) {
            const auto lower = lowercase_copy(value);
            return lower.find("/data/adb") != std::string::npos &&
                   lower.find("zygisk") != std::string::npos;
        }

        void append_tmp_path_marker(
                std::set<std::string> &markers,
                const char *raw_value
        ) {
            if (raw_value == nullptr || raw_value[0] == '\0') {
                return;
            }

            const std::string value(raw_value);
            if (is_zygisk_tmp_path(value)) {
                markers.insert("TMP_PATH=" + value);
            }
        }

    }  // namespace

    ProbeResult collect_environment_probe() {
        ProbeResult result;
        std::set<std::string> markers;

        append_tmp_path_marker(markers, std::getenv("TMP_PATH"));

        if (!markers.empty()) {
            std::ostringstream detail;
            detail << "Environment contains NeoZygisk marker: ";
            size_t index = 0;
            for (const auto &marker: markers) {
                if (index > 0U) {
                    detail << ", ";
                }
                detail << marker;
                index += 1;
            }
            detail << '.';

            result.traces.push_back({
                                            SignalGroup::kRuntime,
                                            SignalSeverity::kDanger,
                                            "NeoZygisk environment marker",
                                            detail.str(),
                                    });
            result.hit_count = static_cast<int>(markers.size());
            result.strong_hits = 1;
        }

        return result;
    }

}  // namespace duckdetector::zygisk
