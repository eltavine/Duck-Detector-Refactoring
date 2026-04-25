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

#include "zygisk/probes/namespace_probe.h"

#include <link.h>
#include <sstream>

namespace duckdetector::zygisk {

    ProbeResult collect_namespace_probe() {
        ProbeResult result;
        std::vector<std::string> restricted_modules;
        dl_iterate_phdr(
                [](dl_phdr_info *info, size_t, void *user_data) -> int {
                    auto *modules = reinterpret_cast<std::vector<std::string> *>(user_data);
                    if (modules == nullptr || info->dlpi_name == nullptr) {
                        return 0;
                    }
                    const std::string name(info->dlpi_name);
                    if (!name.empty() && is_restricted_runtime_path(name)) {
                        modules->push_back(name);
                    }
                    return 0;
                },
                &restricted_modules
        );

        if (!restricted_modules.empty()) {
            std::ostringstream detail;
            detail
                    << "The current process loaded restricted-path libraries through the linker namespace: ";
            for (size_t index = 0; index < restricted_modules.size() && index < 3U; ++index) {
                if (index > 0U) {
                    detail << ", ";
                }
                detail << restricted_modules[index];
            }
            if (restricted_modules.size() > 3U) {
                detail << " and " << (restricted_modules.size() - 3U) << " more";
            }
            detail << '.';
            result.traces.push_back({
                                            SignalGroup::kLinker,
                                            SignalSeverity::kDanger,
                                            "Namespace bypass",
                                            detail.str(),
                                    });
            result.hit_count = static_cast<int>(restricted_modules.size());
            result.strong_hits = 1;
        }

        return result;
    }

}  // namespace duckdetector::zygisk
