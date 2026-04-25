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

#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace duckdetector::zygisk {

    enum class SignalGroup {
        kCrossProcess,
        kRuntime,
        kLinker,
        kMaps,
        kHeap,
        kThreads,
        kFd,
    };

    enum class SignalSeverity {
        kDanger,
        kWarning,
    };

    struct Trace {
        SignalGroup group = SignalGroup::kMaps;
        SignalSeverity severity = SignalSeverity::kWarning;
        std::string label;
        std::string detail;
    };

    struct ProbeResult {
        bool available = true;
        bool supported = true;
        int hit_count = 0;
        int strong_hits = 0;
        int heuristic_hits = 0;
        int numeric_value = 0;
        std::vector<Trace> traces;
    };

    struct Snapshot {
        bool available = false;
        bool heap_available = false;
        bool seccomp_supported = false;
        int tracer_pid = 0;
        int strong_hits = 0;
        int heuristic_hits = 0;
        int solist_hits = 0;
        int vmap_hits = 0;
        int atexit_hits = 0;
        int smaps_hits = 0;
        int namespace_hits = 0;
        int linker_hook_hits = 0;
        int stack_leak_hits = 0;
        int seccomp_hits = 0;
        int heap_hits = 0;
        int thread_hits = 0;
        int fd_hits = 0;
        std::vector<Trace> traces;
    };

    struct MapEntry {
        uintptr_t start = 0;
        uintptr_t end = 0;
        std::string perms;
        uintptr_t offset = 0;
        unsigned long inode = 0;
        std::string path;

        [[nodiscard]] bool readable() const { return perms.find('r') != std::string::npos; }

        [[nodiscard]] bool writable() const { return perms.find('w') != std::string::npos; }

        [[nodiscard]] bool executable() const { return perms.find('x') != std::string::npos; }

        [[nodiscard]] bool private_mapping() const { return perms.find('p') != std::string::npos; }

        [[nodiscard]] bool contains(uintptr_t address) const {
            return address >= start && address < end;
        }
    };

    inline std::string trim_copy(const std::string &value) {
        const auto begin = value.find_first_not_of(" \t\r\n");
        if (begin == std::string::npos) {
            return {};
        }
        const auto end = value.find_last_not_of(" \t\r\n");
        return value.substr(begin, end - begin + 1);
    }

    inline std::string lowercase_copy(std::string value) {
        std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); }
        );
        return value;
    }

    inline bool contains_ignore_case(
            const std::string &haystack,
            const std::string &needle
    ) {
        if (needle.empty()) {
            return false;
        }
        return lowercase_copy(haystack).find(lowercase_copy(needle)) != std::string::npos;
    }

    inline bool starts_with(
            const std::string &value,
            const std::string_view prefix
    ) {
        return value.size() >= prefix.size() &&
               std::equal(prefix.begin(), prefix.end(), value.begin());
    }

    inline std::string read_text_file(const std::string &path) {
        std::ifstream input(path);
        if (!input) {
            return {};
        }
        std::ostringstream output;
        output << input.rdbuf();
        return output.str();
    }

    inline std::vector<std::string> split_lines(const std::string &text) {
        std::vector<std::string> lines;
        std::istringstream input(text);
        std::string line;
        while (std::getline(input, line)) {
            lines.push_back(line);
        }
        return lines;
    }

    inline std::vector<MapEntry> read_proc_maps(const char *path = "/proc/self/maps") {
        std::vector<MapEntry> entries;
        std::ifstream input(path);
        std::string line;
        while (std::getline(input, line)) {
            unsigned long long start = 0;
            unsigned long long end = 0;
            unsigned long long offset = 0;
            unsigned long long inode = 0;
            char perms[5] = {};
            char device[32] = {};
            int path_offset = 0;
            const int matched = std::sscanf(
                    line.c_str(),
                    "%llx-%llx %4s %llx %31s %llu %n",
                    &start,
                    &end,
                    perms,
                    &offset,
                    device,
                    &inode,
                    &path_offset
            );
            if (matched < 6) {
                continue;
            }
            MapEntry entry;
            entry.start = static_cast<uintptr_t>(start);
            entry.end = static_cast<uintptr_t>(end);
            entry.perms = perms;
            entry.offset = static_cast<uintptr_t>(offset);
            entry.inode = static_cast<unsigned long>(inode);
            if (path_offset > 0 && path_offset < static_cast<int>(line.size())) {
                entry.path = trim_copy(line.substr(static_cast<size_t>(path_offset)));
            }
            entries.push_back(std::move(entry));
        }
        return entries;
    }

    inline const MapEntry *find_map_for_address(
            const std::vector<MapEntry> &maps,
            const uintptr_t address
    ) {
        for (const auto &entry: maps) {
            if (entry.contains(address)) {
                return &entry;
            }
        }
        return nullptr;
    }

    inline bool is_restricted_runtime_path(const std::string &path) {
        const auto lower = lowercase_copy(path);
        return lower.find("/data/adb") != std::string::npos ||
               lower.find("/debug_ramdisk") != std::string::npos ||
               lower.find("/sbin/.magisk") != std::string::npos ||
               lower.find("/data/local/tmp") != std::string::npos;
    }

    inline bool is_suspicious_loader_keyword(const std::string &path) {
        const auto lower = lowercase_copy(path);
        return lower.find("zygisk") != std::string::npos ||
               lower.find("magisk") != std::string::npos ||
               lower.find("riru") != std::string::npos ||
               lower.find("rezygisk") != std::string::npos;
    }

    inline std::string format_bytes(const size_t value) {
        constexpr size_t kKiB = 1024;
        constexpr size_t kMiB = 1024 * 1024;
        std::ostringstream output;
        if (value >= kMiB) {
            output.setf(std::ios::fixed);
            output.precision(2);
            output << (static_cast<double>(value) / static_cast<double>(kMiB)) << " MiB";
        } else if (value >= kKiB) {
            output.setf(std::ios::fixed);
            output.precision(1);
            output << (static_cast<double>(value) / static_cast<double>(kKiB)) << " KiB";
        } else {
            output << value << " B";
        }
        return output.str();
    }

}  // namespace duckdetector::zygisk
