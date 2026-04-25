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

#include "playintegrityfix/snapshot_builder.h"

#include "playintegrityfix/probes/maps_probe.h"
#include "playintegrityfix/probes/property_probe.h"

namespace duckdetector::playintegrityfix {

    Snapshot collect_snapshot(const std::vector<std::string> &property_keys) {
        Snapshot snapshot;
        snapshot.available = true;
        snapshot.native_properties = read_properties(property_keys);
        snapshot.runtime_traces = scan_runtime_maps();
        return snapshot;
    }

}  // namespace duckdetector::playintegrityfix
