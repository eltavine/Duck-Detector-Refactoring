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

#include "lsposed/common/codec.h"

#include <sstream>

namespace duckdetector::lsposed {
    namespace {

        std::string escape_value(const std::string &value) {
            std::string escaped;
            escaped.reserve(value.size());
            for (const char ch: value) {
                switch (ch) {
                    case '\\':
                        escaped += "\\\\";
                        break;
                    case '\n':
                        escaped += "\\n";
                        break;
                    case '\r':
                        escaped += "\\r";
                        break;
                    case '\t':
                        escaped += "\\t";
                        break;
                    default:
                        escaped += ch;
                        break;
                }
            }
            return escaped;
        }

    }  // namespace

    const char *to_string(const Severity severity) {
        switch (severity) {
            case Severity::kDanger:
                return "DANGER";
            case Severity::kWarning:
                return "WARNING";
        }
        return "WARNING";
    }

    std::string encode_snapshot(const Snapshot &snapshot) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? '1' : '0') << '\n';
        output << "HEAP_AVAILABLE=" << (snapshot.heap_available ? '1' : '0') << '\n';
        output << "MAPS_HITS=" << snapshot.maps_hit_count << '\n';
        output << "MAPS_SCANNED=" << snapshot.maps_scanned_lines << '\n';
        output << "HEAP_HITS=" << snapshot.heap_hit_count << '\n';
        output << "HEAP_SCANNED=" << snapshot.heap_scanned_regions << '\n';
        for (const NativeTrace &trace: snapshot.traces) {
            output << "TRACE="
                   << trace.group << '\t'
                   << to_string(trace.severity) << '\t'
                   << escape_value(trace.label) << '\t'
                   << escape_value(trace.detail)
                   << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::lsposed
