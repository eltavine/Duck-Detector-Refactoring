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

namespace duckdetector::virtualization {

    struct SnapshotFinding {
        std::string group;
        std::string severity;
        std::string label;
        std::string value;
        std::string detail;
    };

    struct Snapshot {
        bool available = false;
        bool eglAvailable = false;
        std::string eglVendor;
        std::string eglRenderer;
        std::string eglVersion;
        std::string mountNamespaceInode;
        std::string apexMountKey;
        std::string systemMountKey;
        std::string vendorMountKey;
        int mapLineCount = 0;
        int fdCount = 0;
        int mountInfoCount = 0;
        int environmentHitCount = 0;
        int translationHitCount = 0;
        int runtimeArtifactHitCount = 0;
        std::vector<SnapshotFinding> findings;
    };

    Snapshot collect_snapshot();

    std::string encode_snapshot(const Snapshot &snapshot);

}  // namespace duckdetector::virtualization
