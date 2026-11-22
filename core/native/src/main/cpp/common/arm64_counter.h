// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>

namespace duckdetector::common::arm64_counter {

#if defined(__aarch64__)
    inline std::uint64_t read_ticks() {
        std::uint64_t ticks;
        asm volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(ticks) :: "memory");
        return ticks;
    }

    inline std::uint64_t frequency_hz() {
        std::uint64_t frequency;
        asm volatile("isb\n\tmrs %0, cntfrq_el0" : "=r"(frequency) :: "memory");
        return frequency & 0xffff'ffffULL; // CNTFRQ_EL0.ClockFreq is 32 bits.
    }
#endif

    inline bool read_time_ns(std::uint64_t *out_ns) {
#if defined(__aarch64__)
        if (out_ns == nullptr) {
            return false;
        }
        const auto frequency = frequency_hz();
        const auto ticks = read_ticks();
        if (frequency == 0 || ticks == 0) {
            return false;
        }
        constexpr std::uint64_t nanos_per_second = 1'000'000'000ULL;
        const auto seconds = ticks / frequency;
        // Convert separately so uptime cannot overflow the intermediate product.
        if (seconds > (UINT64_MAX - (nanos_per_second - 1)) / nanos_per_second) {
            return false;
        }
        *out_ns = seconds * nanos_per_second + ((ticks % frequency) * nanos_per_second) / frequency;
        return true;
#else
        static_cast<void>(out_ns);
        return false;
#endif
    }

} // namespace duckdetector::common::arm64_counter
