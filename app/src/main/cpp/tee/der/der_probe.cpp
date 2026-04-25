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

#include "tee/der/der_probe.h"

#include <cctype>
#include <sstream>
#include <string>

namespace ducktee::der {
    namespace {

        struct Tlv {
            bool ok = false;
            std::size_t value_offset = 0;
            std::size_t value_length = 0;
            std::size_t next_offset = 0;
            bool non_minimal_length = false;
            std::uint8_t tag = 0;
        };

        Tlv parse_tlv(const std::vector<std::uint8_t> &bytes, std::size_t offset) {
            Tlv tlv;
            if (offset >= bytes.size()) {
                return tlv;
            }

            tlv.tag = bytes[offset];
            if (offset + 1 >= bytes.size()) {
                return tlv;
            }

            const auto first_len = bytes[offset + 1];
            std::size_t header = 2;
            std::size_t value_length = 0;

            if ((first_len & 0x80U) == 0U) {
                value_length = first_len;
            } else {
                const std::size_t bytes_count = first_len & 0x7FU;
                if (bytes_count == 0 || bytes_count > 4 ||
                    offset + 1 + bytes_count >= bytes.size()) {
                    return tlv;
                }
                header += bytes_count;
                for (std::size_t i = 0; i < bytes_count; ++i) {
                    value_length = (value_length << 8U) | bytes[offset + 2 + i];
                }
                if (value_length <= 0x7FU || bytes[offset + 2] == 0x00) {
                    tlv.non_minimal_length = true;
                }
            }

            const std::size_t value_offset = offset + header;
            if (value_offset > bytes.size() || value_length > bytes.size() - value_offset) {
                return tlv;
            }

            tlv.ok = true;
            tlv.value_offset = value_offset;
            tlv.value_length = value_length;
            tlv.next_offset = value_offset + value_length;
            return tlv;
        }

        bool is_hex_template(const std::string &value) {
            if (value.size() != 32) {
                return false;
            }
            for (unsigned char c: value) {
                if (!std::isxdigit(c)) {
                    return false;
                }
            }
            return true;
        }

        void scan_ascii_windows(const std::vector<std::uint8_t> &bytes, DerSnapshot *snapshot) {
            std::string current;
            for (std::uint8_t byte: bytes) {
                const unsigned char c = static_cast<unsigned char>(byte);
                if (std::isprint(c)) {
                    current.push_back(static_cast<char>(c));
                } else {
                    if (is_hex_template(current)) {
                        snapshot->primary_detected = true;
                        snapshot->findings.emplace_back("HEX_TEMPLATE_32");
                    }
                    current.clear();
                }
            }
            if (is_hex_template(current)) {
                snapshot->primary_detected = true;
                snapshot->findings.emplace_back("HEX_TEMPLATE_32");
            }
        }

        bool walk_der_tree(
                const std::vector<std::uint8_t> &bytes,
                std::size_t start,
                std::size_t end,
                int depth,
                DerSnapshot *snapshot) {
            if (depth > 40 || start > end || end > bytes.size()) {
                return false;
            }

            std::size_t cursor = start;
            while (cursor < end) {
                const Tlv tlv = parse_tlv(bytes, cursor);
                if (!tlv.ok || tlv.next_offset > end || tlv.next_offset <= cursor) {
                    return false;
                }
                if (tlv.non_minimal_length) {
                    snapshot->secondary_detected = true;
                    snapshot->findings.emplace_back("NON_MINIMAL_LENGTH");
                }
                if ((tlv.tag & 0x20U) != 0U && tlv.value_length > 0) {
                    if (!walk_der_tree(bytes, tlv.value_offset, tlv.value_offset + tlv.value_length,
                                       depth + 1, snapshot)) {
                        return false;
                    }
                }
                cursor = tlv.next_offset;
            }
            return cursor == end;
        }

    }  // namespace

    DerSnapshot scan_leaf_der(const std::vector<std::uint8_t> &bytes) {
        DerSnapshot snapshot;
        if (bytes.size() < 8) {
            snapshot.findings.emplace_back("DER_MISSING");
            return snapshot;
        }

        scan_ascii_windows(bytes, &snapshot);

        const Tlv top_level = parse_tlv(bytes, 0);
        if (!top_level.ok || top_level.tag != 0x30 || top_level.next_offset != bytes.size()) {
            snapshot.secondary_detected = true;
            snapshot.findings.emplace_back("TOP_LEVEL_SEQUENCE_INVALID");
            return snapshot;
        }

        if (!walk_der_tree(bytes, top_level.value_offset, top_level.next_offset, 0, &snapshot)) {
            snapshot.secondary_detected = true;
            snapshot.findings.emplace_back("DER_TREE_PARSE_FAILURE");
        }

        return snapshot;
    }

}  // namespace ducktee::der
