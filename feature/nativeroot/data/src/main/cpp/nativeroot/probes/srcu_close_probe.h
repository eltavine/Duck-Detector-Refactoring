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

#include <cstdint>
#include <functional>
#include <vector>

namespace duckdetector::nativeroot {
enum class CloseStage { OK, INIT_FAILED, WATCH_FAILED, CLOCK_FAILED, CLOSE_FAILED, THREAD_FAILED };
struct CloseSample {
    std::int64_t begin = 0, end = 0;
    CloseStage stage = CloseStage::OK;
    int error = 0;
};
struct CloseWindow {
    std::int64_t begin = 0, end = 0;
    bool saturated = false;
    std::vector<CloseSample> samples;
};
// Injection is feature-owned and exists to exercise failures without blocking an Android kernel.
struct CloseIo {
    int (*init)();
    int (*watch)(int, const char *);
    int (*close_fd)(int);
    std::int64_t (*now)();
    void (*pause)();
};
CloseWindow measure_close_window(const char *directory, const std::function<void()> &trigger,
                                 const CloseIo *injected = nullptr);
}  // namespace duckdetector::nativeroot
