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

#include "lsposed/snapshot_builder.h"

#include <set>
#include <string>

#include "lsposed/probes/heap_probe.h"
#include "lsposed/probes/maps_probe.h"

namespace duckdetector::lsposed {
    namespace {

        void append_probe(
                Snapshot &snapshot,
                const ProbeResult &probe,
                std::set<std::string> &dedupe
        ) {
            for (const NativeTrace &trace: probe.traces) {
                const std::string key = trace.group + "|" + trace.label + "|" + trace.detail;
                if (!dedupe.insert(key).second) {
                    continue;
                }
                snapshot.traces.push_back(trace);
            }
        }

    }  // namespace

    Snapshot collect_snapshot() {
        Snapshot snapshot;
        snapshot.available = true;

        const ProbeResult maps_probe = scan_runtime_maps();
        const ProbeResult heap_probe = scan_heap_residuals();

        snapshot.heap_available = heap_probe.available;
        snapshot.maps_hit_count = maps_probe.hit_count;
        snapshot.maps_scanned_lines = maps_probe.scanned_count;
        snapshot.heap_hit_count = heap_probe.hit_count;
        snapshot.heap_scanned_regions = heap_probe.scanned_count;

        std::set<std::string> dedupe;
        append_probe(snapshot, maps_probe, dedupe);
        append_probe(snapshot, heap_probe, dedupe);
        return snapshot;
    }

}  // namespace duckdetector::lsposed
