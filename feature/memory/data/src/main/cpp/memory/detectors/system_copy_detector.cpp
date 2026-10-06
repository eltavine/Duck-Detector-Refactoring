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

#include "memory/detectors/system_copy_detector.h"

#include "memory/common/maps_reader.h"
#include "memory/detectors/system_copy_comparison.h"

#include <cstdio>
#include <cstring>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

namespace duckdetector::memory {
    namespace {

        bool is_candidate(const SmapsEntry &entry) {
            return entry.anonymous_kb > 0 &&
                   entry.map.executable &&
                   is_system_path(entry.map.path) &&
                   !is_benign_art_code_cache_path(entry.map.path);
        }

        std::string describe_reason(const CopyComparison &comparison) {
            switch (comparison.reason) {
                case Unverifiable::kPageSizeUnknown:
                    return "the page size is unknown";
                case Unverifiable::kPagemapUnavailable:
                    return "/proc/self/pagemap could not be read";
                case Unverifiable::kPipeUnavailable:
                    return "no pipe was available to read the pages through";
                case Unverifiable::kNotReadable:
                    return "the mapping is not readable";
                case Unverifiable::kFileDeleted:
                    return "the mapped file was deleted";
                case Unverifiable::kFileUnopenable:
                    return std::string("the file could not be opened (") +
                           std::strerror(comparison.open_errno) + ")";
                case Unverifiable::kFileReplaced:
                    return "the path now names a different file than the one mapped";
                case Unverifiable::kNoResidentCopy:
                    return "no copied page was resident when pagemap was read";
                case Unverifiable::kMemoryUnreadable:
                    return "a copied page could not be read";
                case Unverifiable::kFileUnreadable:
                    return "the file could not be read at a copied page's offset";
                case Unverifiable::kBudgetExhausted:
                    return "it has more copied pages than one scan compares";
                case Unverifiable::kNone:
                    break;
            }
            return "the comparison did not finish";
        }

        std::string hex_bytes(
                const std::array<std::uint8_t, kShownDifferenceBytes> &bytes,
                const std::size_t count
        ) {
            std::string text;
            for (std::size_t index = 0; index < count; ++index) {
                char chunk[4];
                std::snprintf(chunk, sizeof(chunk), "%02X", bytes[index]);
                if (index > 0) {
                    text += ' ';
                }
                text += chunk;
            }
            return text;
        }

        Finding make_finding(
                const char *label,
                const FindingSeverity severity,
                std::string detail
        ) {
            return Finding{
                    .section = "MAPS",
                    .category = "SMAPS",
                    .label = label,
                    .detail = std::move(detail),
                    .severity = severity,
            };
        }

        Finding describe(const SmapsEntry &entry, const CopyComparison &comparison) {
            std::ostringstream detail;
            switch (comparison.outcome) {
                case CopyOutcome::kDiffers:
                    detail << entry.map.path << ": " << comparison.differing_pages << " of "
                           << comparison.copied_pages
                           << " privately copied executable page(s) differ from the file, first at"
                           << " file offset 0x" << std::hex << comparison.first_difference
                           << std::dec << " (memory "
                           << hex_bytes(comparison.memory_bytes, comparison.shown_bytes)
                           << ", file " << hex_bytes(comparison.file_bytes, comparison.shown_bytes)
                           << ")";
                    return make_finding("Modified page on system code mapping",
                                        FindingSeverity::kHigh, detail.str());
                case CopyOutcome::kMatches:
                    detail << entry.map.path << ": " << comparison.matching_pages
                           << " privately copied executable page(s) match the file byte for byte";
                    return make_finding("Privately copied system code matches its file",
                                        FindingSeverity::kLow, detail.str());
                case CopyOutcome::kUnverified:
                    break;
            }
            detail << entry.map.path << " reports " << entry.anonymous_kb
                   << " kB anonymous executable pages that could not be compared with the file: "
                   << describe_reason(comparison);
            if (comparison.matching_pages > 0) {
                detail << " (" << comparison.matching_pages << " of " << comparison.copied_pages
                       << " copied pages matched)";
            }
            return make_finding("Anonymous executable pages on system mapping",
                                FindingSeverity::kMedium, detail.str());
        }

    }  // namespace

    SystemCopySignals detect_system_copies(const std::vector<SmapsEntry> &smaps) {
        SystemCopySignals signals;
        std::optional<CopyComparer> comparer;
        for (const SmapsEntry &entry: smaps) {
            if (!is_candidate(entry)) {
                continue;
            }
            if (!comparer.has_value()) {
                comparer.emplace();
            }
            signals.copies_present = true;
            const CopyComparison comparison = comparer->compare(entry.map);
            signals.modified = signals.modified || comparison.outcome == CopyOutcome::kDiffers;
            signals.unverified =
                    signals.unverified || comparison.outcome == CopyOutcome::kUnverified;
            signals.findings.push_back(describe(entry, comparison));
        }
        return signals;
    }

}  // namespace duckdetector::memory
