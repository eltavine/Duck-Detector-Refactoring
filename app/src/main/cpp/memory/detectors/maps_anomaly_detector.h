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

#ifndef DUCKDETECTOR_MEMORY_DETECTORS_MAPS_ANOMALY_DETECTOR_H
#define DUCKDETECTOR_MEMORY_DETECTORS_MAPS_ANOMALY_DETECTOR_H

#include "memory/common/types.h"

#include <vector>

namespace duckdetector::memory {

    MapsSignals detect_maps_anomalies(
            const std::vector<MapEntry> &maps,
            const std::vector<SmapsEntry> &smaps
    );

}  // namespace duckdetector::memory

#endif  // DUCKDETECTOR_MEMORY_DETECTORS_MAPS_ANOMALY_DETECTOR_H
