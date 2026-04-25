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

#include "lsposed/probes/heap_probe.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

namespace duckdetector::lsposed {
    namespace {

        struct Region {
            std::uintptr_t start = 0;
            std::uintptr_t end = 0;
            std::string name;
        };

        constexpr const char *kKeywords[] = {
                "lsposed",
                "org.lsposed",
                "de.robv.android.xposed",
                "xposedbridge",
                "handlehookedmethod",
                "lsplant",
                "libxposed",
                "edxposed",
                "lspatch",
                "lsposed-bridge",
                "lsphooker_",
        };

        constexpr std::size_t kKeywordCount = sizeof(kKeywords) / sizeof(kKeywords[0]);
        constexpr int kMaxRegions = 6;
        constexpr std::size_t kSampleWindowBytes = 256 * 1024;

        std::string to_lower(const std::string &value) {
            std::string lower = value;
            std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            return lower;
        }

        bool is_candidate_region(const char *perms, const std::string &lower_name) {
            if (perms[0] != 'r') {
                return false;
            }
            return lower_name.find("dalvik-main space") != std::string::npos ||
                   lower_name.find("dalvik-data space") != std::string::npos ||
                   lower_name.find("dalvik-large object space") != std::string::npos ||
                   lower_name.find("dalvik-alloc space") != std::string::npos ||
                   lower_name.find("dalvik-zygote space") != std::string::npos;
        }

        std::vector<Region> collect_candidate_regions() {
            std::vector<Region> regions;
            FILE *maps = std::fopen("/proc/self/maps", "r");
            if (maps == nullptr) {
                return regions;
            }

            char line[1024];
            while (std::fgets(line, sizeof(line), maps) != nullptr) {
                unsigned long long start = 0;
                unsigned long long end = 0;
                char perms[5] = {};
                char name[512] = {};
                const int parsed = std::sscanf(
                        line,
                        "%llx-%llx %4s %*s %*s %*s %511[^\n]",
                        &start,
                        &end,
                        perms,
                        name
                );
                if (parsed < 3) {
                    continue;
                }

                const std::string region_name = parsed >= 4 ? std::string(name) : std::string();
                const std::string lower_name = to_lower(region_name);
                if (!is_candidate_region(perms, lower_name)) {
                    continue;
                }

                regions.push_back(
                        Region{
                                .start = static_cast<std::uintptr_t>(start),
                                .end = static_cast<std::uintptr_t>(end),
                                .name = region_name.empty() ? "[unnamed dalvik region]"
                                                            : region_name,
                        }
                );
                if (static_cast<int>(regions.size()) >= kMaxRegions) {
                    break;
                }
            }

            std::fclose(maps);
            return regions;
        }

        bool buffer_contains_keyword(const char *buffer, const std::size_t size) {
            if (buffer == nullptr || size == 0U) {
                return false;
            }

            std::string lower_chunk(buffer, size);
            std::transform(lower_chunk.begin(), lower_chunk.end(), lower_chunk.begin(),
                           [](const unsigned char ch) {
                               return static_cast<char>(std::tolower(ch));
                           });

            for (std::size_t index = 0; index < kKeywordCount; ++index) {
                if (lower_chunk.find(kKeywords[index]) != std::string::npos) {
                    return true;
                }
            }
            return false;
        }

        bool scan_sample_window(
                const int mem_fd,
                const Region &region,
                const std::uintptr_t offset,
                std::vector<char> &buffer
        ) {
            const std::uintptr_t absolute = region.start + offset;
            const std::size_t remaining = static_cast<std::size_t>(region.end - absolute);
            const std::size_t window = std::min(kSampleWindowBytes, remaining);
            if (window == 0U) {
                return false;
            }

            const ssize_t bytes_read = ::pread(mem_fd, buffer.data(), window,
                                               static_cast<off_t>(absolute));
            if (bytes_read <= 0) {
                return false;
            }
            return buffer_contains_keyword(buffer.data(), static_cast<std::size_t>(bytes_read));
        }

        bool region_contains_keyword(
                const int mem_fd,
                const Region &region
        ) {
            const std::size_t region_size = static_cast<std::size_t>(region.end - region.start);
            if (region_size == 0U) {
                return false;
            }

            std::vector<char> buffer(kSampleWindowBytes);
            const std::array<std::uintptr_t, 3> sample_offsets = {
                    0U,
                    region_size > kSampleWindowBytes ? (region_size / 2U) : 0U,
                    region_size > kSampleWindowBytes ? (region_size - kSampleWindowBytes) : 0U,
            };

            std::set<std::uintptr_t> visited_offsets;
            for (const std::uintptr_t sample_offset: sample_offsets) {
                if (!visited_offsets.insert(sample_offset).second) {
                    continue;
                }
                if (scan_sample_window(mem_fd, region, sample_offset, buffer)) {
                    return true;
                }
            }
            return false;
        }

    }  // namespace

    ProbeResult scan_heap_residuals() {
        ProbeResult result;
        const std::vector<Region> regions = collect_candidate_regions();
        result.scanned_count = static_cast<int>(regions.size());

        const int mem_fd = ::open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
        if (mem_fd < 0) {
            result.available = false;
            return result;
        }

        for (const Region &region: regions) {
            if (!region_contains_keyword(mem_fd, region)) {
                continue;
            }
            ++result.hit_count;
            result.traces.push_back(
                    NativeTrace{
                            .group = "HEAP",
                            .label = "Heap residual",
                            .detail = "Keyword sample matched in " + region.name,
                            .severity = Severity::kDanger,
                    }
            );
        }

        ::close(mem_fd);
        return result;
    }

}  // namespace duckdetector::lsposed
