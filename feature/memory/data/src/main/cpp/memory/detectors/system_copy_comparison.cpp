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

#include "memory/detectors/system_copy_comparison.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

namespace duckdetector::memory {
    namespace {

        // Bounds how many pages one scan reads back, so a process full of copies cannot stall it.
        constexpr int kMaxComparedPages = 2048;
        constexpr char kDeletedSuffix[] = " (deleted)";

        std::size_t page_size_or_zero() {
            const long size = sysconf(_SC_PAGESIZE);
            return size > 0 ? static_cast<std::size_t>(size) : 0;
        }

        bool ends_with(const std::string &value, const char *suffix) {
            const std::size_t length = std::strlen(suffix);
            return value.size() >= length &&
                   value.compare(value.size() - length, length, suffix) == 0;
        }

        CopyComparison unverified(const Unverifiable reason) {
            CopyComparison comparison;
            comparison.reason = reason;
            return comparison;
        }

        // The bytes read, fewer than size only past the end of the file, or -1 on an error.
        ssize_t read_file_page(
                const int fd,
                const std::uint64_t offset,
                std::uint8_t *out,
                const std::size_t size
        ) {
            std::size_t done = 0;
            while (done < size) {
                const ssize_t got = TEMP_FAILURE_RETRY(
                        pread64(fd, out + done, size - done, static_cast<off64_t>(offset + done)));
                if (got < 0) {
                    return -1;
                }
                if (got == 0) {
                    break;
                }
                done += static_cast<std::size_t>(got);
            }
            return static_cast<ssize_t>(done);
        }

        // The index of the first byte where the copy differs from the file, or size when none does.
        // The kernel zero-fills the part of a mapped page that lies past the end of the file.
        std::size_t first_difference(
                const std::uint8_t *memory,
                const std::uint8_t *file,
                const std::size_t file_bytes,
                const std::size_t size
        ) {
            if (file_bytes == size && std::memcmp(memory, file, size) == 0) {
                return size;
            }
            for (std::size_t index = 0; index < size; ++index) {
                const std::uint8_t expected = index < file_bytes ? file[index] : 0;
                if (memory[index] != expected) {
                    return index;
                }
            }
            return size;
        }

        void record_difference(
                CopyComparison &comparison,
                const std::uint64_t file_offset,
                const std::size_t at,
                const std::vector<std::uint8_t> &memory,
                const std::vector<std::uint8_t> &contents,
                const std::size_t file_bytes
        ) {
            if (comparison.differing_pages++ > 0) {
                return;
            }
            comparison.first_difference = file_offset + at;
            comparison.shown_bytes = std::min(kShownDifferenceBytes, memory.size() - at);
            for (std::size_t index = 0; index < comparison.shown_bytes; ++index) {
                comparison.memory_bytes[index] = memory[at + index];
                comparison.file_bytes[index] = at + index < file_bytes ? contents[at + index] : 0;
            }
        }

    }  // namespace

    CopyComparer::CopyComparer() : page_size_(page_size_or_zero()), budget_(kMaxComparedPages) {}

    CopyComparison CopyComparer::compare(const MapEntry &map) {
        if (page_size_ == 0) {
            return unverified(Unverifiable::kPageSizeUnknown);
        }
        if (!pagemap_.available()) {
            return unverified(Unverifiable::kPagemapUnavailable);
        }
        if (!memory_.available()) {
            return unverified(Unverifiable::kPipeUnavailable);
        }
        if (!map.readable) {
            return unverified(Unverifiable::kNotReadable);
        }
        if (ends_with(map.path, kDeletedSuffix)) {
            return unverified(Unverifiable::kFileDeleted);
        }

        const ScopedFd file(open(map.path.c_str(), O_RDONLY | O_CLOEXEC));
        if (!file.valid()) {
            CopyComparison comparison = unverified(Unverifiable::kFileUnopenable);
            comparison.open_errno = errno;
            return comparison;
        }
        // The path must still name the file the kernel mapped: after a mount over the path or an
        // update that replaced the file, the copy would be compared with other bytes.
        struct stat status {};
        if (fstat(file.get(), &status) != 0 ||
            major(status.st_dev) != map.dev_major ||
            minor(status.st_dev) != map.dev_minor ||
            static_cast<std::uint64_t>(status.st_ino) != map.inode) {
            return unverified(Unverifiable::kFileReplaced);
        }

        const std::size_t page_count = (map.end - map.start) / page_size_;
        std::vector<PageResidency> residency;
        if (!pagemap_.read(map.start, page_count, page_size_, residency)) {
            return unverified(Unverifiable::kPagemapUnavailable);
        }

        CopyComparison comparison;
        std::vector<std::uint8_t> memory(page_size_);
        std::vector<std::uint8_t> contents(page_size_);
        bool memory_unreadable = false;
        bool file_unreadable = false;
        bool budget_exhausted = false;
        for (std::size_t index = 0; index < page_count; ++index) {
            if (residency[index] != PageResidency::kAnonymousPage) {
                continue;
            }
            ++comparison.copied_pages;
            if (budget_ <= 0) {
                budget_exhausted = true;
                continue;
            }
            --budget_;
            const std::uintptr_t address = map.start + index * page_size_;
            const std::uint64_t file_offset =
                    map.offset + static_cast<std::uint64_t>(index) * page_size_;
            if (!memory_.read(address, page_size_, memory.data())) {
                memory_unreadable = true;
                continue;
            }
            const ssize_t file_bytes =
                    read_file_page(file.get(), file_offset, contents.data(), page_size_);
            if (file_bytes < 0) {
                file_unreadable = true;
                continue;
            }
            const auto read_bytes = static_cast<std::size_t>(file_bytes);
            const std::size_t at =
                    first_difference(memory.data(), contents.data(), read_bytes, page_size_);
            if (at == page_size_) {
                ++comparison.matching_pages;
            } else {
                record_difference(comparison, file_offset, at, memory, contents, read_bytes);
            }
        }

        if (comparison.differing_pages > 0) {
            comparison.outcome = CopyOutcome::kDiffers;
        } else if (comparison.copied_pages == 0) {
            comparison.reason = Unverifiable::kNoResidentCopy;
        } else if (memory_unreadable) {
            comparison.reason = Unverifiable::kMemoryUnreadable;
        } else if (file_unreadable) {
            comparison.reason = Unverifiable::kFileUnreadable;
        } else if (budget_exhausted) {
            comparison.reason = Unverifiable::kBudgetExhausted;
        } else {
            comparison.outcome = CopyOutcome::kMatches;
        }
        return comparison;
    }

}  // namespace duckdetector::memory
