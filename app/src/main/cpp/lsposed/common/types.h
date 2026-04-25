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

#ifndef DUCKDETECTOR_LSPOSED_COMMON_TYPES_H
#define DUCKDETECTOR_LSPOSED_COMMON_TYPES_H

#include <string>
#include <vector>

namespace duckdetector::lsposed {

    enum class Severity {
        kDanger,
        kWarning,
    };

    struct NativeTrace {
        std::string group;
        std::string label;
        std::string detail;
        Severity severity = Severity::kWarning;
    };

    struct ProbeResult {
        bool available = true;
        int hit_count = 0;
        int scanned_count = 0;
        std::vector<NativeTrace> traces;
    };

    struct Snapshot {
        bool available = false;
        bool heap_available = false;
        int maps_hit_count = 0;
        int maps_scanned_lines = 0;
        int heap_hit_count = 0;
        int heap_scanned_regions = 0;
        std::vector<NativeTrace> traces;
    };

    const char *to_string(Severity severity);

}  // namespace duckdetector::lsposed

#endif  // DUCKDETECTOR_LSPOSED_COMMON_TYPES_H
