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

#include "zygisk/probes/heap_entropy_probe.h"

#include <android/api-level.h>
#include <dlfcn.h>

namespace duckdetector::zygisk {

    namespace {

        struct Mallinfo2Compat {
            size_t arena;
            size_t ordblks;
            size_t smblks;
            size_t hblks;
            size_t hblkhd;
            size_t usmblks;
            size_t fsmblks;
            size_t uordblks;
            size_t fordblks;
            size_t keepcost;
        };

        using Mallinfo2Fn = Mallinfo2Compat (*)();

    }  // namespace

    ProbeResult collect_heap_entropy_probe() {
        ProbeResult result;
        if (android_get_device_api_level() < 30) {
            result.supported = false;
            return result;
        }

        const auto *symbol = dlsym(RTLD_DEFAULT, "mallinfo2");
        if (symbol == nullptr) {
            result.supported = false;
            return result;
        }

        const auto mallinfo2_fn = reinterpret_cast<Mallinfo2Fn>(const_cast<void *>(symbol));
        const Mallinfo2Compat info = mallinfo2_fn();
        const size_t allocated = info.uordblks;
        const size_t free_kept = info.fordblks;
        const double ratio =
                allocated > 0U ? static_cast<double>(free_kept) / static_cast<double>(allocated)
                               : 0.0;

        const bool suspicious = (free_kept >= 256U * 1024U && ratio >= 0.20) ||
                                (free_kept >= 512U * 1024U && ratio >= 0.35);
        if (suspicious) {
            result.traces.push_back({
                                            SignalGroup::kHeap,
                                            SignalSeverity::kWarning,
                                            "Heap entropy",
                                            "mallinfo2 reported " + format_bytes(allocated) +
                                            " allocated and " +
                                            format_bytes(free_kept) +
                                            " free-kept heap space (ratio " +
                                            std::to_string(ratio) + ").",
                                    });
            result.hit_count = 1;
            result.heuristic_hits = 1;
        }

        return result;
    }

}  // namespace duckdetector::zygisk
