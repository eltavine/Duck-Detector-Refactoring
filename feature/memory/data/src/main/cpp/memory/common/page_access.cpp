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

#include "memory/common/page_access.h"

#include <fcntl.h>

#include <algorithm>

namespace duckdetector::memory {
    namespace {

        constexpr std::uint64_t kPagePresent = 1ULL << 63;
        constexpr std::uint64_t kPageSwapped = 1ULL << 62;
        constexpr std::uint64_t kPageFileOrSharedAnonymous = 1ULL << 61;

        constexpr std::size_t kPagemapEntriesPerRead = 512;

        // Past pipe-user-pages-soft a new pipe can get a single page of buffer, so each write stays
        // within 4096 bytes, the smallest page size, which an empty pipe takes in one write.
        constexpr std::size_t kPipeChunk = 4096;

        PageResidency classify(const std::uint64_t entry) {
            if ((entry & kPagePresent) != 0) {
                return (entry & kPageFileOrSharedAnonymous) != 0 ? PageResidency::kFilePage
                                                                 : PageResidency::kAnonymousPage;
            }
            return (entry & kPageSwapped) != 0 ? PageResidency::kSwapped
                                               : PageResidency::kNotPresent;
        }

    }  // namespace

    PagemapReader::PagemapReader() : fd_(open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC)) {}

    bool PagemapReader::read(
            const std::uintptr_t start,
            const std::size_t count,
            const std::size_t page_size,
            std::vector<PageResidency> &out
    ) const {
        out.clear();
        if (!available() || page_size == 0) {
            return false;
        }
        out.reserve(count);
        std::uint64_t entries[kPagemapEntriesPerRead];
        const std::uint64_t first_page = start / page_size;
        std::size_t done = 0;
        while (done < count) {
            const std::size_t batch = std::min(kPagemapEntriesPerRead, count - done);
            const std::size_t bytes = batch * sizeof(std::uint64_t);
            const auto offset = static_cast<off64_t>((first_page + done) * sizeof(std::uint64_t));
            const ssize_t got = TEMP_FAILURE_RETRY(pread64(fd_.get(), entries, bytes, offset));
            if (got != static_cast<ssize_t>(bytes)) {
                out.clear();
                return false;
            }
            for (std::size_t index = 0; index < batch; ++index) {
                out.push_back(classify(entries[index]));
            }
            done += batch;
        }
        return true;
    }

    PipeMemoryReader::PipeMemoryReader() {
        int fds[2] = {-1, -1};
        if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) == 0) {
            read_end_.reset(fds[0]);
            write_end_.reset(fds[1]);
        }
    }

    bool PipeMemoryReader::read(
            const std::uintptr_t address,
            const std::size_t size,
            std::uint8_t *out
    ) {
        if (!available()) {
            return false;
        }
        std::size_t done = 0;
        while (done < size) {
            const std::size_t chunk = std::min(kPipeChunk, size - done);
            const ssize_t written = TEMP_FAILURE_RETRY(::write(
                    write_end_.get(), reinterpret_cast<const void *>(address + done), chunk));
            if (written <= 0) {
                drain();
                return false;
            }
            const auto expected = static_cast<std::size_t>(written);
            std::size_t copied = 0;
            while (copied < expected) {
                const ssize_t got = TEMP_FAILURE_RETRY(
                        ::read(read_end_.get(), out + done + copied, expected - copied));
                if (got <= 0) {
                    drain();
                    return false;
                }
                copied += static_cast<std::size_t>(got);
            }
            done += expected;
        }
        return true;
    }

    void PipeMemoryReader::drain() {
        std::uint8_t sink[kPipeChunk];
        while (TEMP_FAILURE_RETRY(::read(read_end_.get(), sink, sizeof(sink))) > 0) {
        }
    }

}  // namespace duckdetector::memory
