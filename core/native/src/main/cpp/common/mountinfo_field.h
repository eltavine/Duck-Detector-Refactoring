// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <charconv>
#include <string_view>
#include <system_error>

namespace duckdetector::common {
    template<typename Integer>
    bool parse_mountinfo_number(std::string_view field, Integer &value) {
        if (field.empty()) return false;
        const auto result = std::from_chars(field.data(), field.data() + field.size(), value);
        return result.ec == std::errc{} && result.ptr == field.data() + field.size();
    }
}
