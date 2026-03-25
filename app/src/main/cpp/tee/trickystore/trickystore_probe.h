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
