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

#include "memory/detectors/function_hook_detector.h"

#include "memory/common/maps_reader.h"

#include <dlfcn.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace duckdetector::memory {
    namespace {

        struct FunctionTarget {
            const char *name;
            std::vector<const char *> expected_module_needles;
        };

        std::vector<std::pair<std::uintptr_t, std::uintptr_t>> module_ranges(
                const std::vector<MapEntry> &maps,
                const std::vector<const char *> &needles
        ) {
            std::vector<std::pair<std::uintptr_t, std::uintptr_t>> ranges;
            for (const MapEntry &entry: maps) {
                for (const char *needle: needles) {
                    if (!entry.path.empty() && entry.path.find(needle) != std::string::npos) {
                        ranges.emplace_back(entry.start, entry.end);
                        break;
                    }
                }
            }
            return ranges;
        }

        bool in_ranges(
                const std::vector<std::pair<std::uintptr_t, std::uintptr_t>> &ranges,
                const std::uintptr_t address
        ) {
            for (const auto &range: ranges) {
                if (address >= range.first && address < range.second) {
                    return true;
                }
            }
            return false;
        }

        std::string hex_prefix(const std::uint8_t *bytes, const size_t count) {
            std::ostringstream output;
            for (size_t index = 0; index < count; ++index) {
                if (index > 0) {
                    output << ' ';
                }
                char chunk[4];
                std::snprintf(chunk, sizeof(chunk), "%02X", bytes[index]);
                output << chunk;
            }
            return output.str();
        }

        bool looks_like_branch_instruction(const std::uint8_t *bytes) {
#if defined(__aarch64__)
            const std::uint32_t inst = *reinterpret_cast<const std::uint32_t*>(bytes);
            return (inst >> 26) == 0x05 ||
                (inst >> 26) == 0x25 ||
                (inst & 0xFFFFFC1F) == 0xD61F0000 ||
                (inst & 0xFFFFFC1F) == 0xD63F0000;
#elif defined(__x86_64__)
            return bytes[0] == 0xE9 ||
                bytes[0] == 0xEB ||
                (bytes[0] == 0xFF && bytes[1] == 0x25) ||
                (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0);
#else
            return false;
#endif
        }

        bool looks_like_expected_prologue(const std::uint8_t *bytes) {
#if defined(__aarch64__)
            const std::uint32_t inst = *reinterpret_cast<const std::uint32_t*>(bytes);
            return (inst & 0xFFC003FF) == 0xA9BF7BFD ||
                (inst & 0xFF8003FF) == 0xD10003FF ||
                inst == 0x910003FD ||
                inst == 0xD503201F ||
                inst == 0xD503233F ||
                (inst & 0x9F000000) == 0x90000000;
#elif defined(__x86_64__)
            return (bytes[0] == 0xF3 && bytes[1] == 0x0F && bytes[2] == 0x1E) ||
                bytes[0] == 0x55 ||
                (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xE5) ||
                (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) ||
                (bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC);
#else
            return false;
#endif
        }

        bool looks_like_trampoline(
                const std::uint8_t *bytes,
                bool *suspicious_jump
        ) {
            *suspicious_jump = false;
#if defined(__aarch64__)
            const std::uint32_t first = *reinterpret_cast<const std::uint32_t*>(bytes);
            const std::uint32_t second = *reinterpret_cast<const std::uint32_t*>(bytes + 4);
            const bool ldr_literal = (first & 0xFF000000) == 0x58000000;
            const bool branch_register = (second & 0xFFFFFC00) == 0xD61F0000;
            if (ldr_literal && branch_register) {
                *suspicious_jump = true;
                return true;
            }
            return (first >> 26) == 0x05 || (first >> 26) == 0x25;
#elif defined(__x86_64__)
            if (bytes[0] == 0xFF && bytes[1] == 0x25) {
                *suspicious_jump = true;
                return true;
            }
            if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0) {
                *suspicious_jump = true;
                return true;
            }
            return false;
#else
            return false;
#endif
        }

        Finding make_finding(
                const char *category,
                const char *label,
                const FindingSeverity severity,
                const std::string &detail
        ) {
            return Finding{
                    .section = "HOOK",
                    .category = category,
                    .label = label,
                    .detail = detail,
                    .severity = severity,
            };
        }

    }  // namespace

    HookSignals detect_function_hooks(const std::vector<MapEntry> &maps) {
        HookSignals signals;
        const std::array<FunctionTarget, 12> targets{{
                                                             {"open", {"libc.so"}},
                                                             {"openat", {"libc.so"}},
                                                             {"read", {"libc.so"}},
                                                             {"write", {"libc.so"}},
                                                             {"stat", {"libc.so"}},
                                                             {"access", {"libc.so"}},
                                                             {"readlink", {"libc.so"}},
                                                             {"mmap", {"libc.so"}},
                                                             {"mprotect", {"libc.so"}},
                                                             {"dlopen",
                                                              {"libdl.so", "linker64", "linker"}},
                                                             {"dlsym",
                                                              {"libdl.so", "linker64", "linker"}},
                                                             {"dlclose",
                                                              {"libdl.so", "linker64", "linker"}},
                                                     }};

        void *global_handle = dlopen(nullptr, RTLD_NOW);
        if (global_handle == nullptr) {
            return signals;
        }

        std::set<std::string> modified_functions;
        for (const FunctionTarget &target: targets) {
            void *address_ptr = dlsym(global_handle, target.name);
            if (address_ptr == nullptr) {
                continue;
            }
            const auto address = reinterpret_cast<std::uintptr_t>(address_ptr);
            const auto entry = find_entry_for_address(maps, address);
            const auto expected_ranges = module_ranges(maps, target.expected_module_needles);
            const std::string resolved_path = entry ? entry->path : "[unmapped]";

            if (!expected_ranges.empty() && !in_ranges(expected_ranges, address)) {
                signals.got_plt_hook = true;
                modified_functions.insert(target.name);
                std::ostringstream detail;
                detail << target.name << " resolved to " << resolved_path << " @ 0x"
                       << std::hex << address;
                signals.findings.push_back(
                        make_finding("GOT_PLT", "Resolved address escaped expected module",
                                     FindingSeverity::kHigh, detail.str())
                );
            }

            if (!entry.has_value() || !entry->readable) {
                continue;
            }

            const auto *bytes = static_cast<const std::uint8_t *>(address_ptr);
            if (looks_like_branch_instruction(bytes) && !looks_like_expected_prologue(bytes)) {
                signals.inline_hook = true;
                signals.prologue_modified = true;
                modified_functions.insert(target.name);
                std::ostringstream detail;
                detail << target.name << " starts with branch-like bytes [" << hex_prefix(bytes, 12)
                       << "]";
                signals.findings.push_back(
                        make_finding("INLINE_HOOK", "Branch-like prologue", FindingSeverity::kHigh,
                                     detail.str())
                );
            }

            bool suspicious_jump = false;
            if (looks_like_trampoline(bytes, &suspicious_jump)) {
                signals.trampoline = true;
                signals.suspicious_jump = signals.suspicious_jump || suspicious_jump;
                modified_functions.insert(target.name);
                std::ostringstream detail;
                detail << target.name << " shows a trampoline-style entry ["
                       << hex_prefix(bytes, 12) << "]";
                signals.findings.push_back(
                        make_finding(
                                "TRAMPOLINE",
                                suspicious_jump ? "Trampoline with jump handoff"
                                                : "Trampoline-style entry",
                                suspicious_jump ? FindingSeverity::kHigh : FindingSeverity::kMedium,
                                detail.str()
                        )
                );
            }
        }

        signals.modified_function_count = static_cast<int>(modified_functions.size());
        dlclose(global_handle);
        return signals;
    }

}  // namespace duckdetector::memory
