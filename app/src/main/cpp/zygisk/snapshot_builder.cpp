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

#include "zygisk/snapshot_builder.h"

#include "zygisk/probes/atexit_probe.h"
#include "zygisk/probes/fd_probe.h"
#include "zygisk/probes/heap_entropy_probe.h"
#include "zygisk/probes/linker_hook_probe.h"
#include "zygisk/probes/namespace_probe.h"
#include "zygisk/probes/smaps_probe.h"
#include "zygisk/probes/solist_probe.h"
#include "zygisk/probes/thread_probe.h"
#include "zygisk/probes/vmap_probe.h"

namespace duckdetector::zygisk {

    namespace {

        void merge_probe(
                Snapshot &snapshot,
                const ProbeResult &probe
        ) {
            snapshot.strong_hits += probe.strong_hits;
            snapshot.heuristic_hits += probe.heuristic_hits;
            snapshot.traces.insert(snapshot.traces.end(), probe.traces.begin(), probe.traces.end());
        }

    }  // namespace

    Snapshot collect_snapshot() {
        Snapshot snapshot;
        const auto maps = read_proc_maps();
        if (maps.empty()) {
            return snapshot;
        }

        snapshot.available = true;

        const auto solist = collect_solist_probe();
        const auto vmap = collect_vmap_probe();
        const auto atexit = collect_atexit_probe();
        const auto smaps = collect_smaps_probe();
        const auto namespace_probe = collect_namespace_probe();
        const auto linker_hook = collect_linker_hook_probe();
        const auto heap = collect_heap_entropy_probe();
        const auto threads = collect_thread_probe();
        const auto fd = collect_fd_probe();

        snapshot.heap_available = heap.supported;
        snapshot.seccomp_supported = false;
        snapshot.tracer_pid = threads.numeric_value;

        snapshot.solist_hits = solist.hit_count;
        snapshot.vmap_hits = vmap.hit_count;
        snapshot.atexit_hits = atexit.hit_count;
        snapshot.smaps_hits = smaps.hit_count;
        snapshot.namespace_hits = namespace_probe.hit_count;
        snapshot.linker_hook_hits = linker_hook.hit_count;
        snapshot.stack_leak_hits = 0;
        snapshot.seccomp_hits = 0;
        snapshot.heap_hits = heap.hit_count;
        snapshot.thread_hits = threads.hit_count;
        snapshot.fd_hits = fd.hit_count;

        merge_probe(snapshot, solist);
        merge_probe(snapshot, vmap);
        merge_probe(snapshot, atexit);
        merge_probe(snapshot, smaps);
        merge_probe(snapshot, namespace_probe);
        merge_probe(snapshot, linker_hook);
        merge_probe(snapshot, heap);
        merge_probe(snapshot, threads);
        merge_probe(snapshot, fd);

        return snapshot;
    }

}  // namespace duckdetector::zygisk
