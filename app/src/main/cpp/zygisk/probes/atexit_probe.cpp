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

#include "zygisk/probes/atexit_probe.h"

#include <dlfcn.h>

namespace duckdetector::zygisk {

    ProbeResult collect_atexit_probe() {
        ProbeResult result;
        const auto maps = read_proc_maps();
        if (maps.empty()) {
            result.available = false;
            return result;
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
            result.heuristic_hits = 1;
        }

        return result;
    }

}  // namespace duckdetector::zygisk
