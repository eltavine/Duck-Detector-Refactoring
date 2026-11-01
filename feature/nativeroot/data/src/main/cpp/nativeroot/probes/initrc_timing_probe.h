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

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <sys/stat.h>

namespace duckdetector::nativeroot {

// Wire codes are shared only with this feature's InitRcTimingNativeBridge.
enum class InitRcTimingStage {
    COLLECTED, UNSUPPORTED_ABI, FILE_FAILED, THREAD_FAILED, NAME_FAILED,
    AFFINITY_FAILED, CLOCK_FAILED, SYSCALL_FAILED, TIMED_OUT, CLEANUP_FAILED,
};
constexpr std::size_t kInitRcRounds = 32;
constexpr int kInitRcIterations = 128;
// Each condition is indexed by (comm == init) * 2 + (filename == init.rc).
using InitRcRound = std::array<std::int64_t, 4>;
struct InitRcTimingResult {
    InitRcTimingStage stage = InitRcTimingStage::COLLECTED;
    int error = 0;
    int cleanup_error = 0;
    int cpu = -1;
    bool cleanup_complete = false;
    std::size_t count = 0;
    std::array<InitRcRound, kInitRcRounds> rounds{};
};

// A narrow test seam for the measured platform behavior; file ownership uses real private files.
struct InitRcTimingIo {
    int (*set_name)(const char *);
    int (*get_name)(char *);
    int (*pin_cpu)();
    int (*current_cpu)();
    int (*stat_fd)(int, struct stat *);
    std::int64_t (*now)();
    int (*verify_affinity)(int expected_cpu);
};

InitRcTimingResult collect_initrc_timing(const char *private_directory,
                                       const InitRcTimingIo *injected = nullptr);
}  // namespace duckdetector::nativeroot
