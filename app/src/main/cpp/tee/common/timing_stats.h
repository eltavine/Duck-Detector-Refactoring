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
