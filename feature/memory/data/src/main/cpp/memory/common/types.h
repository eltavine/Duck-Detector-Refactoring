/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

#ifndef DUCKDETECTOR_MEMORY_COMMON_TYPES_H
#define DUCKDETECTOR_MEMORY_COMMON_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace duckdetector::memory {

    enum class FindingSeverity {
        kCritical,
        kHigh,
        kMedium,
        kLow,
    };

    struct Finding {
        std::string section;
        std::string category;
        std::string label;
        std::string detail;
        FindingSeverity severity = FindingSeverity::kLow;
    };

    struct MapEntry {
        std::uintptr_t start = 0;
        std::uintptr_t end = 0;
        bool readable = false;
        bool writable = false;
        bool executable = false;
        bool private_mapping = false;
        // The file offset of start and the device and inode of the mapped file, as maps prints them.
        std::uint64_t offset = 0;
        unsigned int dev_major = 0;
        unsigned int dev_minor = 0;
        std::uint64_t inode = 0;
        std::string path;
    };

    struct SmapsEntry {
        MapEntry map;
        int anonymous_kb = 0;
        int swap_kb = 0;
        int shared_dirty_kb = 0;
        std::string vm_flags;
    };

    struct HookSignals {
        // Set once dlopen(nullptr) gave a handle to resolve the targets through.
        bool checks_ran = false;
        // The entry-byte heuristics decode arm64 and x86_64 instructions only.
        bool entry_checks_supported = false;
        bool got_plt_hook = false;
        bool inline_hook = false;
        bool prologue_modified = false;
        bool trampoline = false;
        bool suspicious_jump = false;
        int modified_function_count = 0;
        std::vector<Finding> findings;
    };

    struct MapsSignals {
        bool writable_exec = false;
        bool anonymous_exec = false;
        bool swapped_exec = false;
        bool shared_dirty_exec = false;
        std::vector<Finding> findings;
    };

    // Pages of executable system file mappings that became private copies, which smaps counts as
    // Anonymous. A write makes one, but on kernels whose get_user_pages forces a COW break so does
    // any read that pins the page, such as printing an anonymous VMA name in /proc/self/maps on
    // ACK 4.19, so only the copy's bytes tell whether the code was changed.
    struct SystemCopySignals {
        bool copies_present = false;
        // A copy holds bytes the file does not have at the same offset.
        bool modified = false;
        // A copy could not be compared with the file, so whether it was changed is unknown.
        bool unverified = false;
        std::vector<Finding> findings;
    };

    struct FdSignals {
        bool deleted_so = false;
        bool suspicious_memfd = false;
        bool exec_ashmem = false;
        bool dev_zero_exec = false;
        std::vector<Finding> findings;
    };

    struct SignalSignals {
        bool suspicious_handler = false;
        bool frida_named_handler = false;
        bool anonymous_handler = false;
        std::vector<Finding> findings;
    };

    struct VdsoSignals {
        // False when the kernel mapped no vDSO into this process, leaving nothing to check.
        bool checks_ran = false;
        bool remapped = false;
        bool unusual_base = false;
        std::vector<Finding> findings;
    };

    struct LinkerSignals {
        bool deleted_library = false;
        bool hidden_module = false;
        bool maps_only_module = false;
        std::vector<Finding> findings;
    };

    struct Snapshot {
        bool available = false;
        HookSignals hooks;
        MapsSignals maps;
        SystemCopySignals copies;
        FdSignals fd;
        SignalSignals signal;
        VdsoSignals vdso;
        LinkerSignals linker;
    };

    std::vector<Finding> collect_all_findings(const Snapshot &snapshot);

    int count_findings_by_severity(const Snapshot &snapshot, FindingSeverity severity);

    const char *to_string(FindingSeverity severity);

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_COMMON_TYPES_H
