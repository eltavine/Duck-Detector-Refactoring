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

#include "playintegrityfix/common/codec.h"

#include <sstream>
#include <string>

namespace duckdetector::playintegrityfix {
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

    const char *to_string(const TraceSeverity severity) {
        switch (severity) {
            case TraceSeverity::kDanger:
                return "DANGER";
            case TraceSeverity::kWarning:
                return "WARNING";
        }
        return "WARNING";
    }

    std::string encode_snapshot(const Snapshot &snapshot) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? '1' : '0') << '\n';
        for (const auto &[key, value]: snapshot.native_properties) {
            output << "PROP=" << key << "|" << escape_value(value) << '\n';
        }
        for (const RuntimeTrace &trace: snapshot.runtime_traces) {
            output << "TRACE="
                   << to_string(trace.severity) << '\t'
                   << trace.label << '\t'
                   << escape_value(trace.detail)
                   << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::playintegrityfix
