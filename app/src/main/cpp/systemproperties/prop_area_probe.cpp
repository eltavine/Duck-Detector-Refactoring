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

#include "systemproperties/prop_area_probe.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <sys/system_properties.h>

namespace systemproperties {
    namespace {

        constexpr const char *kPropDir = "/dev/__properties__";
        constexpr std::string_view kSerialFilename = "properties_serial";
        constexpr std::string_view kPropertyInfoFilename = "property_info";
        constexpr uint32_t kPropAreaMagic = 0x504f5250U;
        constexpr uint32_t kPropAreaVersion = 0xfc6ed0abU;
        constexpr uint32_t kLongFlag = 1U << 16;
        constexpr size_t kByteAlignment = 4;
        constexpr size_t kDirtyBackupAreaSize = PROP_VALUE_MAX;
        constexpr size_t kMaxHoleSamples = 3;

#ifdef O_NOFOLLOW
        constexpr int kOpenReadFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
#else
        constexpr int kOpenReadFlags = O_RDONLY | O_CLOEXEC;
#endif

        struct DiskPropAreaHeader {
            uint32_t bytes_used;
            uint32_t serial;
            uint32_t magic;
            uint32_t version;
            uint32_t reserved[28];
            uint8_t data[0];
        };

        struct DiskPropTrieNode {
            uint32_t namelen;
            uint32_t prop;
            uint32_t left;
            uint32_t right;
            uint32_t children;
            char name[0];
        };

        struct DiskLongProperty {
            char error_message[56];
            uint32_t offset;
        };

        struct DiskPropInfo {
            uint32_t serial;
            union {
                char value[PROP_VALUE_MAX];
                DiskLongProperty long_property;
            };
            char name[0];
        };

        struct HoleRun {
            uint32_t offset;
            size_t length;
        };

        struct ParsedAreaResult {
            bool parsed = false;
            std::optional<PropAreaFinding> finding;
        };

        size_t align_up(size_t value) {
            return (value + (kByteAlignment - 1)) & ~(kByteAlignment - 1);
        }

        bool is_skipped_entry(const char *name) {
            if (name == nullptr) {
                return true;
            }
            return std::strcmp(name, ".") == 0 ||
                   std::strcmp(name, "..") == 0 ||
                   kSerialFilename == name ||
                   kPropertyInfoFilename == name;
        }

        std::string hex_offset(uint32_t offset) {
            std::ostringstream stream;
            stream << "0x" << std::hex << std::nouppercase << offset;
            return stream.str();
        }

        class PropAreaParser {
        public:
            PropAreaParser(const uint8_t *data, size_t bytes_used)
                    : data_(data),
                      bytes_used_(bytes_used),
                      occupied_(bytes_used, 0) {}

            bool parse(std::vector<HoleRun> *holes) {
                if (holes == nullptr || data_ == nullptr) {
                    return false;
                }

                const auto *root = object_at<DiskPropTrieNode>(0);
                if (root == nullptr || root->namelen != 0) {
                    return false;
                }

                if (!mark_range(0, sizeof(DiskPropTrieNode))) {
                    return false;
                }
                if (!mark_range(static_cast<uint32_t>(sizeof(DiskPropTrieNode)),
                                kDirtyBackupAreaSize)) {
                    return false;
                }

                if (!visit_root(root)) {
                    return false;
                }

                return collect_holes(holes);
            }

        private:
            template<typename T>
            const T *object_at(uint32_t offset) const {
                if (offset > bytes_used_) {
                    return nullptr;
                }
                if (bytes_used_ - offset < sizeof(T)) {
                    return nullptr;
                }
                return reinterpret_cast<const T *>(data_ + offset);
            }

            bool visit_root(const DiskPropTrieNode *root) {
                return visit_trie(root->left) &&
                       visit_trie(root->right) &&
                       visit_trie(root->children) &&
                       visit_prop(root->prop);
            }

            bool visit_trie(uint32_t offset) {
                if (offset == 0) {
                    return true;
                }
                if (!visited_nodes_.insert(offset).second) {
                    return true;
                }

                const auto *node = object_at<DiskPropTrieNode>(offset);
                if (node == nullptr) {
                    return false;
                }

                const uint32_t name_offset =
                        offset + static_cast<uint32_t>(sizeof(DiskPropTrieNode));
                const auto name_length = bounded_c_string_length(name_offset);
                if (!name_length.has_value() || *name_length != node->namelen) {
                    return false;
                }

                const size_t allocation_size = align_up(
                        sizeof(DiskPropTrieNode) + node->namelen + 1U);
                if (!mark_range(offset, allocation_size)) {
                    return false;
                }

                return visit_trie(node->left) &&
                       visit_trie(node->right) &&
                       visit_trie(node->children) &&
                       visit_prop(node->prop);
            }

            bool visit_prop(uint32_t offset) {
                if (offset == 0) {
                    return true;
                }
                if (!visited_props_.insert(offset).second) {
                    return true;
                }

                const auto *prop = object_at<DiskPropInfo>(offset);
                if (prop == nullptr) {
                    return false;
                }

                const uint32_t name_offset = offset + static_cast<uint32_t>(sizeof(DiskPropInfo));
                const auto name_length = bounded_c_string_length(name_offset);
                if (!name_length.has_value()) {
                    return false;
                }

                const size_t allocation_size = align_up(sizeof(DiskPropInfo) + *name_length + 1U);
                if (!mark_range(offset, allocation_size)) {
                    return false;
                }

                if ((prop->serial & kLongFlag) == 0) {
                    return true;
                }

                const uint32_t relative_offset = prop->long_property.offset;
                if (relative_offset < sizeof(DiskPropInfo)) {
                    return false;
                }

                const uint32_t long_value_offset = offset + relative_offset;
                if (long_value_offset >= bytes_used_) {
                    return false;
                }

                const auto value_length = bounded_c_string_length(long_value_offset);
                if (!value_length.has_value()) {
                    return false;
                }

                return mark_range(long_value_offset, align_up(*value_length + 1U));
            }

            std::optional<size_t> bounded_c_string_length(uint32_t offset) const {
                if (offset >= bytes_used_) {
                    return std::nullopt;
                }
                const void *terminator = std::memchr(data_ + offset, '\0', bytes_used_ - offset);
                if (terminator == nullptr) {
                    return std::nullopt;
                }
                return static_cast<const uint8_t *>(terminator) - (data_ + offset);
            }

            bool mark_range(uint32_t offset, size_t size) {
                if (size == 0) {
                    return true;
                }
                if (offset % kByteAlignment != 0 || size % kByteAlignment != 0) {
                    return false;
                }
                if (offset > bytes_used_ || size > bytes_used_ - offset) {
                    return false;
                }
                std::fill(
                        occupied_.begin() + static_cast<std::ptrdiff_t>(offset),
                        occupied_.begin() + static_cast<std::ptrdiff_t>(offset + size),
                        1
                );
                return true;
            }

            bool collect_holes(std::vector<HoleRun> *holes) const {
                size_t index = 0;
                while (index < bytes_used_) {
                    if (occupied_[index] != 0) {
                        ++index;
                        continue;
                    }

                    const size_t start = index;
                    while (index < bytes_used_ && occupied_[index] == 0) {
                        ++index;
                    }
                    const size_t length = index - start;
                    if (start % kByteAlignment != 0 || length < kByteAlignment ||
                        length % kByteAlignment != 0) {
                        return false;
                    }
                    holes->push_back(
                            HoleRun{
                                    .offset = static_cast<uint32_t>(start),
                                    .length = length,
                            }
                    );
                }
                return true;
            }

            const uint8_t *data_;
            size_t bytes_used_;
            std::vector<uint8_t> occupied_;
            std::unordered_set<uint32_t> visited_nodes_;
            std::unordered_set<uint32_t> visited_props_;
        };

        std::optional<ParsedAreaResult>
        scan_area(const std::string &path, const std::string &context) {
            const int fd = open(path.c_str(), kOpenReadFlags);
            if (fd < 0) {
                return std::nullopt;
            }

            struct stat stat_buffer{};
            if (fstat(fd, &stat_buffer) != 0 || !S_ISREG(stat_buffer.st_mode)) {
                close(fd);
                return std::nullopt;
            }

            if (static_cast<size_t>(stat_buffer.st_size) < sizeof(DiskPropAreaHeader)) {
                close(fd);
                return std::nullopt;
            }

            void *mapping = mmap(nullptr, static_cast<size_t>(stat_buffer.st_size), PROT_READ,
                                 MAP_PRIVATE, fd, 0);
            close(fd);
            if (mapping == MAP_FAILED) {
                return std::nullopt;
            }

            const auto *header = reinterpret_cast<const DiskPropAreaHeader *>(mapping);
            const size_t data_size =
                    static_cast<size_t>(stat_buffer.st_size) - sizeof(DiskPropAreaHeader);
            ParsedAreaResult result;

            if (header->magic == kPropAreaMagic &&
                header->version == kPropAreaVersion &&
                header->bytes_used <= data_size &&
                header->bytes_used >= sizeof(DiskPropTrieNode) + kDirtyBackupAreaSize) {
                std::vector<HoleRun> holes;
                PropAreaParser parser(header->data, header->bytes_used);
                if (parser.parse(&holes)) {
                    result.parsed = true;
                    if (!holes.empty()) {
                        std::ostringstream detail;
                        detail << "Found hole in prop area: " << context;
                        detail << " (" << holes.size() << " hole(s))";
                        detail << " ranges ";
                        const size_t sample_count = std::min(holes.size(), kMaxHoleSamples);
                        for (size_t index = 0; index < sample_count; ++index) {
                            if (index > 0) {
                                detail << ", ";
                            }
                            detail << '@' << hex_offset(holes[index].offset) << '+'
                                   << holes[index].length;
                        }
                        if (holes.size() > sample_count) {
                            detail << ", ...";
                        }
                        result.finding = PropAreaFinding{
                                .context = context,
                                .hole_count = static_cast<int>(holes.size()),
                                .detail = detail.str(),
                        };
                    }
                }
            }

            munmap(mapping, static_cast<size_t>(stat_buffer.st_size));
            return result.parsed ? std::optional<ParsedAreaResult>(result) : std::nullopt;
        }

    }  // namespace

    PropAreaSnapshot scan_prop_area_holes() {
        PropAreaSnapshot snapshot;

        DIR *directory = opendir(kPropDir);
        if (directory == nullptr) {
            return snapshot;
        }

        while (dirent *entry = readdir(directory)) {
            if (is_skipped_entry(entry->d_name)) {
                continue;
            }

            const std::string context(entry->d_name);
            const std::string path = std::string(kPropDir) + "/" + context;
            const auto finding = scan_area(path, context);
            if (!finding.has_value()) {
                continue;
            }

            snapshot.available = true;
            ++snapshot.context_count;
            if (finding->finding.has_value()) {
                snapshot.hole_count += finding->finding->hole_count;
                snapshot.findings.push_back(*finding->finding);
            }
        }

        closedir(directory);
        return snapshot;
    }

}  // namespace systemproperties
