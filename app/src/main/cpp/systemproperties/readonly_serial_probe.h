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

#pragma once

#include <string>
#include <vector>

namespace systemproperties {

    struct ReadOnlyPropertySerialFinding {
        std::string property;
        int suspicious_sample_count = 0;
        std::string low24_hex;
        std::string detail;
    };

    struct ReadOnlyPropertySerialSnapshot {
        bool available = false;
        int checked_count = 0;
        int finding_count = 0;
        std::vector<ReadOnlyPropertySerialFinding> findings;
    };

    ReadOnlyPropertySerialSnapshot
    scan_readonly_property_serials(const std::vector<std::string> &properties);

}  // namespace systemproperties
