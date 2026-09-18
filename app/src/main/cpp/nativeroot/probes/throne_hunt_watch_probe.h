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

#ifndef DUCKDETECTOR_NATIVEROOT_PROBES_THRONE_HUNT_WATCH_PROBE_H
#define DUCKDETECTOR_NATIVEROOT_PROBES_THRONE_HUNT_WATCH_PROBE_H

#include <string>

namespace duckdetector::nativeroot {

    // Result of the app_zygote-side watch stage. The watch fd itself is deliberately not part
    // of this struct: it is inherited by the isolated child through fork, which is the whole
    // point of running the watch from the preload carrier.
    struct ThroneHuntWatchResult {
        bool watch_installed = false;
        bool watch_add_denied = false;
        int watch_descriptor = -1;
        int error_number = 0;
        std::string detail;
        std::string package_directory;
    };

    // Creates an inotify instance and adds the app's own /data/app/<pkg>-<hash> directory so the
    // KernelSU throne hunt (search_manager -> filp_open + iterate_dir) shows up as an
    // IN_OPEN/IN_ACCESS on the directory inode. Runs in the app_zygote context, so the returned
    // descriptor survives into the isolated child.
    ThroneHuntWatchResult install_throne_hunt_watch(const std::string &package_directory);

    // Non-blocking drain of the inherited watch descriptor. Returns the number of directory
    // IN_OPEN/IN_ACCESS events seen since the previous call and appends them to `detail`.
    struct ThroneHuntEventSummary {
        int directory_open_count = 0;
        int directory_access_count = 0;
        int raw_event_count = 0;
        int invalid_count = 0;
        std::string detail;
    };

    ThroneHuntEventSummary drain_throne_hunt_watch(int watch_descriptor);

    // Reading the event stream without consuming it keeps the carrier stateless across calls.
    void reset_throne_hunt_watch(int watch_descriptor);

}  // namespace duckdetector::nativeroot

#endif  // DUCKDETECTOR_NATIVEROOT_PROBES_THRONE_HUNT_WATCH_PROBE_H
