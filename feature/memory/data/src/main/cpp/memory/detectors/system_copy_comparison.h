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

#ifndef DUCKDETECTOR_MEMORY_DETECTORS_SYSTEM_COPY_COMPARISON_H
#define DUCKDETECTOR_MEMORY_DETECTORS_SYSTEM_COPY_COMPARISON_H

#include "memory/common/page_access.h"
#include "memory/common/types.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace duckdetector::memory {

    enum class CopyOutcome {
        kMatches,
        kDiffers,
        kUnverified,
    };

    enum class Unverifiable {
        kNone,
        kPageSizeUnknown,
        kPagemapUnavailable,
        kPipeUnavailable,
        kNotReadable,
        kFileDeleted,
        kFileUnopenable,
        kFileReplaced,
        kNoResidentCopy,
        kMemoryUnreadable,
        kFileUnreadable,
        kBudgetExhausted,
    };

    inline constexpr std::size_t kShownDifferenceBytes = 4;

    struct CopyComparison {
        CopyOutcome outcome = CopyOutcome::kUnverified;
        Unverifiable reason = Unverifiable::kNone;
        int open_errno = 0;
        int copied_pages = 0;
        int matching_pages = 0;
        int differing_pages = 0;
        // The first differing byte as a file offset, with the bytes from there in memory and file.
        std::uint64_t first_difference = 0;
        std::size_t shown_bytes = 0;
        std::array<std::uint8_t, kShownDifferenceBytes> memory_bytes{};
        std::array<std::uint8_t, kShownDifferenceBytes> file_bytes{};
    };

    // Compares the privately copied pages of file mappings with the files, sharing pagemap, the
    // pipe and a page budget across the mappings of one scan.
    class CopyComparer {
    public:
        CopyComparer();

        CopyComparison compare(const MapEntry &map);

    private:
        std::size_t page_size_;
        PagemapReader pagemap_;
        PipeMemoryReader memory_;
        int budget_;
    };

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_DETECTORS_SYSTEM_COPY_COMPARISON_H
