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

#include "memory/snapshot_builder.h"

#include "memory/common/maps_reader.h"
#include "memory/detectors/fd_detector.h"
#include "memory/detectors/function_hook_detector.h"
#include "memory/detectors/linker_detector.h"
#include "memory/detectors/maps_anomaly_detector.h"
#include "memory/detectors/signal_detector.h"
#include "memory/detectors/vdso_detector.h"

namespace duckdetector::memory {

    Snapshot collect_snapshot() {
        Snapshot snapshot;
        const auto maps = read_self_maps();
        if (maps.empty()) {
            snapshot.available = false;
            return snapshot;
        }

        snapshot.available = true;
        const auto smaps = read_self_smaps();
        snapshot.hooks = detect_function_hooks(maps);
        snapshot.maps = detect_maps_anomalies(maps, smaps);
        snapshot.fd = detect_fd_anomalies(maps);
        snapshot.signal = detect_signal_anomalies(maps);
        snapshot.vdso = detect_vdso_anomalies(maps);
        snapshot.linker = detect_linker_anomalies(maps);
        return snapshot;
    }

}  // namespace duckdetector::memory
