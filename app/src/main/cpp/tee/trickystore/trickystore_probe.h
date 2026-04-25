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

#ifndef DUCKDETECTOR_TEE_TRICKYSTORE_PROBE_H
#define DUCKDETECTOR_TEE_TRICKYSTORE_PROBE_H

#include <cstdint>
#include <string>
#include <vector>

namespace ducktee::trickystore {

    struct ProbeSnapshot {
        bool detected = false;
        bool got_hook_detected = false;
        bool syscall_mismatch_detected = false;
        bool inline_hook_detected = false;
        bool honeypot_detected = false;
        int honeypot_run_count = 0;
        int honeypot_suspicious_run_count = 0;
        std::uint64_t honeypot_median_gap_ns = 0;
        std::uint64_t honeypot_gap_mad_ns = 0;
        std::uint64_t honeypot_median_noise_floor_ns = 0;
        int honeypot_median_ratio_percent = 0;
        std::string timer_source = "unknown";
        std::string timer_fallback_reason;
        std::string affinity_status = "not_requested";
        std::string details;
        std::vector<std::string> methods;
    };

    ProbeSnapshot inspect_process();

}  // namespace ducktee::trickystore

#endif  // DUCKDETECTOR_TEE_TRICKYSTORE_PROBE_H
