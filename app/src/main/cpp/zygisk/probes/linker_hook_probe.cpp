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

#include "zygisk/probes/linker_hook_probe.h"

#include <dlfcn.h>

namespace duckdetector::zygisk {

    namespace {

        bool suspicious_owner_path(const std::string &path) {
            const auto lower = lowercase_copy(path);
            return lower.find("linker") == std::string::npos &&
                   lower.find("libdl.so") == std::string::npos;
        }

        bool arm64_branch_leaves_owner(
                const MapEntry &owner,
                const void *symbol
        ) {
#if defined(__aarch64__)
            if (!owner.readable()) {
                return false;
            }
            const auto address = reinterpret_cast<uintptr_t>(symbol);
            const auto instruction = *reinterpret_cast<const uint32_t*>(symbol);
            if ((instruction & 0xFC000000U) != 0x14000000U) {
                return false;
            }
            int32_t immediate = static_cast<int32_t>(instruction & 0x03FFFFFFU);
            if ((immediate & 0x02000000) != 0) {
                immediate |= static_cast<int32_t>(0xFC000000U);
            }
            const uintptr_t target = address + (static_cast<intptr_t>(immediate) << 2);
            return !owner.contains(target);
#else
            (void) owner;
            (void) symbol;
            return false;
#endif
        }

    }  // namespace

    ProbeResult collect_linker_hook_probe() {
        ProbeResult result;
        const auto maps = read_proc_maps();
        if (maps.empty()) {
            result.available = false;
            return result;
        }

        const std::pair<const char *, void *> targets[] = {
                {"dlopen",  dlsym(RTLD_DEFAULT, "dlopen")},
                {"dlsym",   dlsym(RTLD_DEFAULT, "dlsym")},
                {"dlclose", dlsym(RTLD_DEFAULT, "dlclose")},
        };

        for (const auto &[name, address]: targets) {
            if (address == nullptr) {
                continue;
            }
            const auto *owner = find_map_for_address(maps, reinterpret_cast<uintptr_t>(address));
            if (owner == nullptr || suspicious_owner_path(owner->path) ||
                arm64_branch_leaves_owner(*owner, address)) {
                result.traces.push_back({
                                                SignalGroup::kLinker,
                                                SignalSeverity::kDanger,
                                                "Linker hook",
                                                std::string(name) +
                                                " resolves outside the expected linker image or immediately branches away from it.",
                                        });
                break;
            }
        }

        if (!result.traces.empty()) {
            result.hit_count = 1;
            result.strong_hits = 1;
        }
        return result;
    }

}  // namespace duckdetector::zygisk
