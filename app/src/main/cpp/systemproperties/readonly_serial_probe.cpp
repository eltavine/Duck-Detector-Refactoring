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

#include "systemproperties/readonly_serial_probe.h"

#include <sys/system_properties.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace systemproperties {
    namespace {

        constexpr std::string_view kReadOnlyPrefix = "ro.";
        constexpr std::string_view kAppCompatOverridePrefix = "ro.appcompat_override.";
        constexpr uint32_t kLow24Mask = 0x00ffffffU;
        constexpr uint32_t kLongFlag = 1U << 16;
        constexpr size_t kSampleCount = 3;

        bool is_readonly_property(const std::string &property) {
            return property.starts_with(kReadOnlyPrefix) &&
                   !property.starts_with(kAppCompatOverridePrefix);
        }

        bool is_allowed_low24(uint32_t low24) {
            return low24 == 0U || low24 == kLongFlag;
        }

        std::string hex_value(uint32_t value, int width) {
            std::ostringstream stream;
            stream << "0x"
                   << std::hex
                   << std::nouppercase
                   << std::setw(width)
                   << std::setfill('0')
                   << value;
            return stream.str();
        }

        std::optional<ReadOnlyPropertySerialFinding>
        inspect_property(const std::string &property) {
            const prop_info *info = __system_property_find(property.c_str());
            if (info == nullptr) {
                return std::nullopt;
            }

            std::array<uint32_t, kSampleCount> serial_samples{};
            int suspicious_sample_count = 0;
            uint32_t abnormal_low24 = 0U;

            for (size_t index = 0; index < kSampleCount; ++index) {
                const uint32_t serial = __system_property_serial(info);
                serial_samples[index] = serial;

                const uint32_t low24 = serial & kLow24Mask;
                if (!is_allowed_low24(low24)) {
                    ++suspicious_sample_count;
                    abnormal_low24 = low24;
                }
            }

            if (suspicious_sample_count < 2) {
                return std::nullopt;
            }

            std::ostringstream detail;
            detail << "Read-only property low-24 update field was non-zero in "
                   << suspicious_sample_count
                   << '/'
                   << kSampleCount
                   << " native libc sample(s). low24="
                   << hex_value(abnormal_low24, 6)
                   << ". raw serials=";
            for (size_t index = 0; index < serial_samples.size(); ++index) {
                if (index > 0) {
                    detail << ", ";
                }
                detail << hex_value(serial_samples[index], 8);
            }
            detail
                    << ". AOSP ro.* properties are write-once after init, so their low-24 update field should stay zero; long ro.* values may carry kLongFlag instead.";

            return ReadOnlyPropertySerialFinding{
                    .property = property,
                    .suspicious_sample_count = suspicious_sample_count,
                    .low24_hex = hex_value(abnormal_low24, 6),
                    .detail = detail.str(),
            };
        }

    }  // namespace

    ReadOnlyPropertySerialSnapshot
    scan_readonly_property_serials(const std::vector<std::string> &properties) {
        ReadOnlyPropertySerialSnapshot snapshot;

        std::set<std::string> candidates;
        for (const std::string &property: properties) {
            if (is_readonly_property(property)) {
                candidates.insert(property);
            }
        }

        for (const std::string &property: candidates) {
            const prop_info *info = __system_property_find(property.c_str());
            if (info == nullptr) {
                continue;
            }

            snapshot.available = true;
            ++snapshot.checked_count;

            const auto finding = inspect_property(property);
            if (finding.has_value()) {
                snapshot.findings.push_back(*finding);
            }
        }

        snapshot.finding_count = static_cast<int>(snapshot.findings.size());
        return snapshot;
    }

}  // namespace systemproperties
