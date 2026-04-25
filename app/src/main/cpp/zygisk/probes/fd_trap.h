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

namespace duckdetector::zygisk {

    constexpr int kFdTrapClean = 0;
    constexpr int kFdTrapEbadf = 1;
    constexpr int kFdTrapCorruption = 2;
    constexpr int kFdTrapProcfsAnomaly = 3;
    constexpr int kFdTrapBindFailed = -2;
    constexpr int kFdTrapTimeout = -3;
    constexpr int kFdTrapNativeUnavailable = -4;

    int setup_trap_fd(const std::string &cache_dir);

    int verify_trap_fd(int fd);

    std::string get_trap_details();

    void cleanup_trap_fd(int fd);

}  // namespace duckdetector::zygisk
