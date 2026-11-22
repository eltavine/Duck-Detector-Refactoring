// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <optional>

namespace duckdetector::selinux {

    struct RawContextNodeResult {
        int open_error = 0;
        int write_error = 0;
        bool complete = false;
        std::optional<std::int64_t> elapsed_ns;

        [[nodiscard]] bool rejected() const;
    };

    RawContextNodeResult query_raw_context_node(const char *context, bool measure_write);

}  // namespace duckdetector::selinux
