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

#include "zygisk/probes/stack_leak_probe.h"

#include <array>
#include <cstring>

namespace duckdetector::zygisk {

ProbeResult collect_stack_leak_probe() {
    ProbeResult result;
    const auto maps = read_proc_maps();
    const MapEntry* stack_map = nullptr;
    for (const auto& entry : maps) {
        if (entry.readable() && entry.path.find("[stack]") != std::string::npos) {
            stack_map = &entry;
            break;
        }
    }
    if (stack_map == nullptr || stack_map->end <= stack_map->start) {
        result.available = false;
        return result;
    }

    const size_t length = static_cast<size_t>(stack_map->end - stack_map->start);
    if (length == 0U || length > (8U * 1024U * 1024U)) {
        result.supported = false;
        return result;
    }

    const char stack_marker = 0;
    const auto current_sp = reinterpret_cast<uintptr_t>(&stack_marker);
    if (!stack_map->contains(current_sp)) {
        result.supported = false;
        return result;
    }

    constexpr size_t kScanWindowBytes = 256U * 1024U;
    const auto window_start = current_sp > kScanWindowBytes ? current_sp - kScanWindowBytes : stack_map->start;
    const auto begin_address = std::max(stack_map->start, window_start);
    const auto end_address = std::min(stack_map->end, current_sp + 4096U);
    if (end_address <= begin_address) {
        result.supported = false;
        return result;
    }

    const char* begin = reinterpret_cast<const char*>(begin_address);
    const char* end = reinterpret_cast<const char*>(end_address);
    constexpr std::array<std::string_view, 5> kKeywords = {
        "zygisk",
        "magisk",
        "rezygisk",
        "debug_ramdisk",
        "riru",
    };
    for (const auto keyword : kKeywords) {
        const auto* location = std::search(begin, end, keyword.begin(), keyword.end());
        if (location != end) {
            result.traces.push_back({
                SignalGroup::kRuntime,
                SignalSeverity::kWarning,
                "Stack leak",
                "Current thread stack window still contains the keyword '" + std::string(keyword) + "' near 0x" +
                    std::to_string(reinterpret_cast<uintptr_t>(location)) + '.',
            });
            result.hit_count = 1;
            result.heuristic_hits = 1;
            break;
        }
    }

    return result;
}

}  // namespace duckdetector::zygisk
