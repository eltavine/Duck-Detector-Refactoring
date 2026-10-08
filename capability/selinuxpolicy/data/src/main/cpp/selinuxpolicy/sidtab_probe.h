/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

#ifndef DUCKDETECTOR_SELINUX_SIDTAB_PROBE_H
#define DUCKDETECTOR_SELINUX_SIDTAB_PROBE_H

#include <array>
#include <cstdint>
#include <string>
#include <type_traits>

namespace duckdetector::selinux::sidtab {

    // Two rounds of four candidates, plus the carrier control: at most nine entries per table.
    constexpr unsigned kRounds = 2;
    constexpr unsigned kSamples = 4;
    constexpr unsigned kContextBytes = 256;
    enum class State { kNotCollected, kComplete, kUnsupported, kPermissionLimited, kUnavailable, kInconclusive };
    enum class Step { kSetup, kCarrier, kControls, kContext, kAttrCurrent, kRepeat, kFinished };

    struct Sample {
        char context[kContextBytes]{};
        int context_error = -1;
        int attr_error = -1;
        int repeat_error = -1;
    };
    struct Round {
        int64_t before_controls = -1;
        int64_t before = -1;
        int64_t after_context = -1;
        int64_t after_attr = -1;
        int64_t after_repeat = -1;
        int64_t idle_end = -1;
        int positive_error = -1;
        int negative_error = -1;
        int attr_negative_error = -1;
        std::array<Sample, kSamples> samples{};
    };
    // Fixed-size child report: no allocation or Java/libselinux calls after fork.
    struct Report {
        State state = State::kInconclusive;
        Step step = Step::kSetup;
        int error = 0;
        unsigned completed_rounds = 0;
        bool canonical_mismatch = false;
        bool identity_changed = false;
        char carrier[kContextBytes]{};
        std::array<Round, kRounds> rounds{};
    };
    static_assert(std::is_trivially_copyable_v<Report>);
    struct Result {
        Report report{};
        bool attempted = false;
        int uid = -1;
        int pid = -1;
        int signal = 0;
        int64_t captured_uptime_ms = -1;
        std::string kernel_release;
        std::string child_end;
    };

    Result collect();

} // namespace duckdetector::selinux::sidtab
#endif
