#include "tee/common/timing_stats.h"

#include <algorithm>

namespace ducktee::common {

    namespace {

        std::size_t percentile_index(const std::size_t size, const std::size_t percentile) {
            if (size == 0) {
                return 0;
            }
            return ((size - 1U) * percentile) / 100U;
        }

    }  // namespace

    std::uint64_t median_of_samples(std::vector<std::uint64_t> values) {
        if (values.empty()) {
            return 0;
        }
        std::sort(values.begin(), values.end());
        return values[values.size() / 2U];
    }

    SampleStats summarize_samples(std::vector<std::uint64_t> values) {
        SampleStats stats;
        if (values.empty()) {
            return stats;
        }

        std::sort(values.begin(), values.end());
        stats.available = true;
        stats.min_ns = values.front();
        stats.median_ns = values[values.size() / 2U];
        stats.p95_ns = values[percentile_index(values.size(), 95U)];
        stats.max_ns = values.back();

        std::vector<std::uint64_t> deviations;
        deviations.reserve(values.size());
        for (const auto value: values) {
            deviations.push_back(value >= stats.median_ns
                                 ? (value - stats.median_ns)
                                 : (stats.median_ns - value));
        }
        std::sort(deviations.begin(), deviations.end());
        stats.mad_ns = deviations[deviations.size() / 2U];
        return stats;
    }

}  // namespace ducktee::common
