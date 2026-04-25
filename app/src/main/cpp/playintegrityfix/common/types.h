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

#ifndef DUCKDETECTOR_PLAYINTEGRITYFIX_COMMON_TYPES_H
#define DUCKDETECTOR_PLAYINTEGRITYFIX_COMMON_TYPES_H

#include <map>
#include <string>
#include <vector>

namespace duckdetector::playintegrityfix {

    enum class TraceSeverity {
        kDanger,
        kWarning,
    };

    struct RuntimeTrace {
        std::string label;
        std::string detail;
        TraceSeverity severity = TraceSeverity::kWarning;
    };

    struct Snapshot {
        bool available = false;
        std::map<std::string, std::string> native_properties;
        std::vector<RuntimeTrace> runtime_traces;
    };

    const char *to_string(TraceSeverity severity);

}  // namespace duckdetector::playintegrityfix

#endif  // DUCKDETECTOR_PLAYINTEGRITYFIX_COMMON_TYPES_H
