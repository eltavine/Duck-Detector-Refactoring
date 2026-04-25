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
#include <vector>

namespace duckdetector::preload::virtualization {

    struct EarlyVirtualizationResult {
        bool hasRun = false;
        bool detected = false;
        bool qemuPropertyDetected = false;
        bool emulatorHardwareDetected = false;
        bool deviceNodeDetected = false;
        bool avfRuntimeDetected = false;
        bool authfsRuntimeDetected = false;
        bool nativeBridgeDetected = false;
        std::string mountNamespaceInode;
        std::string apexMountKey;
        std::string systemMountKey;
        std::string vendorMountKey;
        std::string detectionMethod;
        std::string details;
        std::vector<std::string> findings;
    };

    EarlyVirtualizationResult run_early_detection();

    const EarlyVirtualizationResult *get_stored_result();

    bool has_early_detection_run();

    bool is_preload_context_valid();

    void reset_early_detection();

}  // namespace duckdetector::preload::virtualization
