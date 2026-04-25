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

#ifndef DUCKDETECTOR_TEE_DER_DER_PROBE_H
#define DUCKDETECTOR_TEE_DER_DER_PROBE_H

#include <cstdint>
#include <vector>

namespace ducktee::der {

    struct DerSnapshot {
        bool primary_detected = false;
        bool secondary_detected = false;
        std::vector<std::string> findings;
    };

    DerSnapshot scan_leaf_der(const std::vector<std::uint8_t> &bytes);

}  // namespace ducktee::der

#endif  // DUCKDETECTOR_TEE_DER_DER_PROBE_H
