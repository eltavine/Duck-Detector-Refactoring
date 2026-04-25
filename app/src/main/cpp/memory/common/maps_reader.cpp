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

#include "memory/common/maps_reader.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <initializer_list>

namespace duckdetector::memory {
    namespace {

        std::string trim_ascii(std::string value) {
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
                value.erase(value.begin());
            }
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
                value.pop_back();
            }
            return value;
        }

        MapEntry parse_map_line(const char *line) {
            MapEntry entry;
            unsigned long start = 0;
            unsigned long end = 0;
            char perms[5] = {};
            unsigned long inode = 0;
            int path_offset = 0;
            if (std::sscanf(
                    line,
                    "%lx-%lx %4s %*s %*s %lu %n",
                    &start,
                    &end,
                    perms,
                    &inode,
                    &path_offset
            ) < 4) {
                return entry;
            }

            entry.start = static_cast<std::uintptr_t>(start);
            entry.end = static_cast<std::uintptr_t>(end);
            entry.readable = perms[0] == 'r';
            entry.writable = perms[1] == 'w';
            entry.executable = perms[2] == 'x';
            entry.private_mapping = perms[3] == 'p';
            entry.inode = inode;
            if (path_offset > 0 && static_cast<size_t>(path_offset) < std::strlen(line)) {
                entry.path = trim_ascii(std::string(line + path_offset));
            }
            return entry;
        }

        bool starts_with(
                const std::string &value,
                const char *prefix
        ) {
            return value.rfind(prefix, 0) == 0;
        }

        bool contains_any(
                const std::string &value,
                const std::initializer_list<const char *> needles
        ) {
            for (const char *needle: needles) {
                if (value.find(needle) != std::string::npos) {
                    return true;
                }
            }
            return false;
        }

        bool contains_known_art_code_cache_name(const std::string &lowered) {
            return contains_any(
                    lowered,
                    {
                            "dalvik-jit-code-cache",
                            "dalvik-data-code-cache",
                            "dalvik-zygote-jit-code-cache",
                            "dalvik-zygote-data-code-cache",
                            "jit-cache",
                            "jit-zygote-cache",
                            "jit-code-cache",
                            "zygote-jit-code-cache",
                            "data-code-cache",
                            "zygote-data-code-cache",
                    }
            );
        }

        bool is_known_app_code_cache_path(const std::string &lowered) {
            return starts_with(lowered, "/memfd:jit-cache") ||
                   starts_with(lowered, "/memfd:/jit-cache") ||
                   starts_with(lowered, "/dev/ashmem/jit-cache") ||
                   starts_with(lowered, "/dev/ashmem//jit-cache") ||
                   starts_with(lowered, "/dev/ashmem/dalvik-jit-code-cache") ||
                    starts_with(lowered, "/dev/ashmem/dalvik-data-code-cache") ||
                    starts_with(lowered, "[anon:dalvik-jit-code-cache]") ||
                    starts_with(lowered, "[anon:dalvik-jit-code-cache") ||
                    starts_with(lowered, "[anon:dalvik-data-code-cache]") ||
                    starts_with(lowered, "[anon:dalvik-data-code-cache");
        }

        bool is_known_zygote_code_cache_path(const std::string &lowered) {
            return starts_with(lowered, "/memfd:jit-zygote-cache") ||
                   starts_with(lowered, "/memfd:/jit-zygote-cache") ||
                   starts_with(lowered, "/dev/ashmem/jit-zygote-cache") ||
                   starts_with(lowered, "/dev/ashmem//jit-zygote-cache") ||
                    starts_with(lowered, "/dev/ashmem/dalvik-zygote-jit-code-cache") ||
                    starts_with(lowered, "/dev/ashmem/dalvik-zygote-data-code-cache") ||
                    starts_with(lowered, "[anon:dalvik-zygote-jit-code-cache]") ||
                    starts_with(lowered, "[anon:dalvik-zygote-jit-code-cache") ||
                    starts_with(lowered, "[anon:dalvik-zygote-data-code-cache]") ||
                    starts_with(lowered, "[anon:dalvik-zygote-data-code-cache");
        }

        bool is_benign_runtime_memfd_path(const std::string &lowered) {
            if (!starts_with(lowered, "/memfd:") && !starts_with(lowered, "memfd:")) {
                return false;
            }
            return contains_any(
                    lowered,
                    {
                            "jit-cache",
                            "jit-zygote-cache",
                            "gralloc",
                            "hwui",
                            "fresco",
                            "fontmap",
                            "gfxstats",
                            "skia",
                    }
            );
        }

    }  // namespace

    std::vector<MapEntry> read_self_maps() {
        std::vector<MapEntry> maps;
        FILE *fp = std::fopen("/proc/self/maps", "r");
        if (fp == nullptr) {
            return maps;
        }

        char line[768];
        while (std::fgets(line, sizeof(line), fp) != nullptr) {
            MapEntry entry = parse_map_line(line);
            if (entry.end > entry.start) {
                maps.push_back(std::move(entry));
            }
        }
        std::fclose(fp);
        return maps;
    }

    std::vector<SmapsEntry> read_self_smaps() {
        std::vector<SmapsEntry> entries;
        FILE *fp = std::fopen("/proc/self/smaps", "r");
        if (fp == nullptr) {
            return entries;
        }

        char line[768];
        SmapsEntry current;
        bool has_current = false;
        while (std::fgets(line, sizeof(line), fp) != nullptr) {
            MapEntry header = parse_map_line(line);
            if (header.end > header.start) {
                if (has_current) {
                    entries.push_back(current);
                }
                current = SmapsEntry{};
                current.map = std::move(header);
                has_current = true;
                continue;
            }
            if (!has_current) {
                continue;
            }

            int value_kb = 0;
            if (std::sscanf(line, "Anonymous: %d kB", &value_kb) == 1) {
                current.anonymous_kb = value_kb;
                continue;
            }
            if (std::sscanf(line, "Swap: %d kB", &value_kb) == 1) {
                current.swap_kb = value_kb;
                continue;
            }
            if (std::sscanf(line, "Shared_Dirty: %d kB", &value_kb) == 1) {
                current.shared_dirty_kb = value_kb;
                continue;
            }
            if (std::strncmp(line, "VmFlags:", 8) == 0) {
                current.vm_flags = trim_ascii(std::string(line + 8));
            }
        }
        if (has_current) {
            entries.push_back(current);
        }
        std::fclose(fp);
        return entries;
    }

    std::optional<MapEntry> find_entry_for_address(
            const std::vector<MapEntry> &maps,
            const std::uintptr_t address
    ) {
        for (const MapEntry &entry: maps) {
            if (address >= entry.start && address < entry.end) {
                return entry;
            }
        }
        return std::nullopt;
    }

    bool is_system_path(const std::string &path) {
        return path.rfind("/system/", 0) == 0 ||
               path.rfind("/system_ext/", 0) == 0 ||
               path.rfind("/vendor/", 0) == 0 ||
               path.rfind("/product/", 0) == 0 ||
               path.rfind("/odm/", 0) == 0 ||
               path.rfind("/apex/", 0) == 0;
    }

    bool is_benign_art_code_cache_path(const std::string &path) {
        const std::string lowered = to_lower_ascii(path);
        if (is_known_app_code_cache_path(lowered) || is_known_zygote_code_cache_path(lowered)) {
            return true;
        }
        if ((starts_with(lowered, "[anon:") || starts_with(lowered, "[anon_shmem:")) &&
            contains_known_art_code_cache_name(lowered)) {
            return true;
        }
        if ((starts_with(lowered, "/memfd:") ||
             starts_with(lowered, "memfd:") ||
             starts_with(lowered, "/dev/ashmem/")) &&
            contains_known_art_code_cache_name(lowered)) {
            return true;
        }
        if ((starts_with(lowered, "dalvik-") ||
             starts_with(lowered, "jit-") ||
             starts_with(lowered, "zygote-") ||
             starts_with(lowered, "data-")) &&
            contains_known_art_code_cache_name(lowered)) {
            return true;
        }
        return false;
    }

    bool is_probably_jit_path(const std::string &path) {
        return is_benign_art_code_cache_path(path);
    }

    bool is_suspicious_loader_path(const std::string &path) {
        const std::string lowered = to_lower_ascii(path);
        return lowered.find("frida") != std::string::npos ||
               lowered.find("gadget") != std::string::npos ||
               lowered.find("zygisk") != std::string::npos ||
               lowered.find("riru") != std::string::npos ||
               lowered.find("magisk") != std::string::npos ||
               lowered.find("kernelsu") != std::string::npos ||
               lowered.find("apatch") != std::string::npos ||
               lowered.find("/data/adb/") != std::string::npos ||
               lowered.find("/data/local/tmp") != std::string::npos;
    }

    bool is_benign_loader_artifact_path(const std::string &path) {
        const std::string lowered = to_lower_ascii(path);
        if (is_probably_jit_path(lowered)) {
            return true;
        }
        if (is_benign_runtime_memfd_path(lowered)) {
            return true;
        }
        if (lowered.rfind("/dev/ashmem", 0) == 0) {
            return true;
        }
        return lowered.find("gfxstats-") != std::string::npos ||
               lowered.find("fontmap") != std::string::npos;
    }

    bool is_anonymous_path(const std::string &path) {
        return path.empty() ||
               path == "[anon]" ||
               path.rfind("[anon:", 0) == 0 ||
               path.rfind("/dev/zero", 0) == 0;
    }

    std::string basename_of(const std::string &path) {
        const size_t slash = path.find_last_of('/');
        if (slash == std::string::npos) {
            return path;
        }
        return path.substr(slash + 1);
    }

    std::string to_lower_ascii(std::string value) {
        std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); }
        );
        return value;
    }

}  // namespace duckdetector::memory
