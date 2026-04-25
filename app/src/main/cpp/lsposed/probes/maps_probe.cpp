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

#include "lsposed/probes/maps_probe.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <set>
#include <string>

namespace duckdetector::lsposed {
    namespace {

        struct Signature {
            const char *token;
            const char *label;
            Severity severity;
        };

        constexpr Signature kSignatures[] = {
                {"lsposed",                "LSPosed runtime mapping",      Severity::kDanger},
                {"org.lsposed",            "LSPosed package mapping",      Severity::kDanger},
                {"libxposed",              "libXposed runtime mapping",    Severity::kDanger},
                {"xposedbridge",           "XposedBridge runtime mapping", Severity::kDanger},
                {"de.robv.android.xposed", "Xposed API runtime mapping",   Severity::kDanger},
                {"lsplant",                "LSPlant runtime mapping",      Severity::kDanger},
                {"lspd.dex",               "LSPosed dex mapping",          Severity::kDanger},
                {"lspd.so",                "LSPosed native mapping",       Severity::kDanger},
                {"liblspd",                "LSPosed bridge mapping",       Severity::kDanger},
                {"edxposed",               "EdXposed runtime mapping",     Severity::kDanger},
                {"libedxp",                "EdXposed native mapping",      Severity::kDanger},
                {"lspatch",                "LSPatch runtime mapping",      Severity::kDanger},
        };

        std::string to_lower(const std::string &value) {
            std::string lower = value;
            std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            return lower;
        }

        std::string extract_mapping_target(const std::string &line) {
            const std::size_t slash = line.find('/');
            if (slash != std::string::npos) {
                return line.substr(slash);
            }
            const std::size_t bracket = line.find('[');
            if (bracket != std::string::npos) {
                return line.substr(bracket);
            }
            return line;
        }

    }  // namespace

    ProbeResult scan_runtime_maps() {
        ProbeResult result;

        FILE *maps = std::fopen("/proc/self/maps", "r");
        if (maps == nullptr) {
            result.available = false;
            return result;
        }

        std::set<std::string> dedupe;
        char line[1024];
        while (std::fgets(line, sizeof(line), maps) != nullptr) {
            ++result.scanned_count;
            const std::string raw_line(line);
            const std::string lower_line = to_lower(raw_line);
            for (const Signature &signature: kSignatures) {
                if (lower_line.find(signature.token) == std::string::npos) {
                    continue;
                }
                const std::string evidence = extract_mapping_target(raw_line);
                const std::string key = std::string(signature.label) + "|" + evidence;
                if (!dedupe.insert(key).second) {
                    continue;
                }
                ++result.hit_count;
                result.traces.push_back(
                        NativeTrace{
                                .group = "MAPS",
                                .label = signature.label,
                                .detail = evidence,
                                .severity = signature.severity,
                        }
                );
            }
        }

        std::fclose(maps);
        return result;
    }

}  // namespace duckdetector::lsposed
