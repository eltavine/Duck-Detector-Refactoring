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

#ifndef DUCKDETECTOR_TEE_COMMON_TIMING_STATS_H
#define DUCKDETECTOR_TEE_COMMON_TIMING_STATS_H

#include <cstdint>
#include <vector>

namespace ducktee::common {

    struct SampleStats {
        bool available = false;
        std::uint64_t min_ns = 0;
        std::uint64_t median_ns = 0;
        std::uint64_t p95_ns = 0;
        std::uint64_t max_ns = 0;
        std::uint64_t mad_ns = 0;
    };

    std::uint64_t median_of_samples(std::vector<std::uint64_t> values);

    SampleStats summarize_samples(std::vector<std::uint64_t> values);

}  // namespace ducktee::common

#endif  // DUCKDETECTOR_TEE_COMMON_TIMING_STATS_H
