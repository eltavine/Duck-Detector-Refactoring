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

#ifndef DUCKDETECTOR_MOUNT_DETECTOR_CORE_H
#define DUCKDETECTOR_MOUNT_DETECTOR_CORE_H

#include <string>
#include <vector>

namespace duckdetector::mount {

    struct MountFindingRecord {
        std::string group;
        std::string severity;
        std::string label;
        std::string value;
        std::string detail;
    };

    struct MountSnapshot {
        bool available = true;
        bool mountsReadable = false;
        bool mountInfoReadable = false;
        bool mapsReadable = false;
        bool filesystemsReadable = false;
        bool initNamespaceReadable = false;
        bool statxSupported = false;

        int permissionTotal = 0;
        int permissionDenied = 0;
        int permissionAccessible = 0;
        int mountEntryCount = 0;
        int mountInfoEntryCount = 0;
        int mapLineCount = 0;

        bool busyboxDetected = false;
        bool magiskMountDetected = false;
        bool zygiskCacheDetected = false;
        bool systemRwDetected = false;
        bool overlayMountDetected = false;
        bool namespaceAnomalyDetected = false;
        bool dataAdbDetected = false;
        bool debugRamdiskDetected = false;
        bool hybridMountDetected = false;
        bool metaHybridMountDetected = false;
        bool suspiciousTmpfsDetected = false;
        bool ksuOverlayDetected = false;
        bool loopDeviceDetected = false;
        bool dmVerityBypassDetected = false;
        bool mountPropagationAnomaly = false;
        bool inconsistentMountDetected = false;
        bool mountIdLoopholeDetected = false;
        bool peerGroupLoopholeDetected = false;
        bool minorDevLoopholeDetected = false;
        bool futileHideDetected = false;
        bool statxMntIdMismatch = false;
        bool bindMountDetected = false;
        bool mountOptionsAnomaly = false;
        bool statxMountRootAnomaly = false;
        bool overlayfsKernelSupport = false;
        bool systemFsTypeAnomaly = false;
        bool tmpfsSizeAnomaly = false;

        std::vector<MountFindingRecord> findings;
    };

    MountSnapshot collect_snapshot();

    std::string encode_snapshot(const MountSnapshot &snapshot);

}  // namespace duckdetector::mount

#endif  // DUCKDETECTOR_MOUNT_DETECTOR_CORE_H
