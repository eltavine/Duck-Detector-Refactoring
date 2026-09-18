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

#include "nativeroot/probes/throne_hunt_watch_probe.h"

#include <cerrno>
#include <cstring>
#include <string>

#include <sys/inotify.h>
#include <unistd.h>

namespace duckdetector::nativeroot {
    namespace {

        // KernelSU's manager/pkg_observer.c watches /data/system for FS_CREATE|FS_MOVE on
        // "packages.list" and calls track_throne(false). track_throne then runs
        // search_manager("/data/app", 2), whose my_actor does filp_open(dirpath, O_RDONLY |
        // O_NOFOLLOW) followed by iterate_dir() on every package directory inode.
        // An inotify watch placed on our own package directory therefore observes an
        // IN_OPEN + IN_ACCESS pair with an empty name that no ordinary app activity produces.
        constexpr int kWatchMask = IN_OPEN | IN_ACCESS;
        constexpr int kReadBufferSize = 4096;

        struct inotify_event_header {
            int wd;
            std::uint32_t mask;
            std::uint32_t cookie;
            std::uint32_t len;
            char name[];
        };

    }  // namespace

    ThroneHuntWatchResult install_throne_hunt_watch(const std::string &package_directory) {
        ThroneHuntWatchResult result;
        result.package_directory = package_directory;

        const int inotify_fd = inotify_init();
        if (inotify_fd < 0) {
            result.error_number = errno;
            result.detail = "inotify_init failed: " + std::string(std::strerror(errno));
            return result;
        }

        const int watch_fd = inotify_add_watch(inotify_fd, package_directory.c_str(), kWatchMask);
        if (watch_fd < 0) {
            result.error_number = errno;
            // inotify_add_watch goes through inode_permission(..., MAY_READ), so a denied watch
            // means the app_zygote context cannot read the directory rather than a policy quirk.
            result.detail = "inotify_add_watch denied for " + package_directory + ": " +
                            std::string(std::strerror(errno));
            close(inotify_fd);
            return result;
        }

        result.watch_installed = true;
        result.watch_descriptor = inotify_fd;
        result.detail = "Watching " + package_directory + " for throne hunt IN_OPEN/IN_ACCESS.";
        return result;
    }

    ThroneHuntEventSummary drain_throne_hunt_watch(const int watch_descriptor) {
        ThroneHuntEventSummary summary;
        if (watch_descriptor < 0) {
            summary.detail = "No inherited throne hunt watch descriptor.";
            return summary;
        }

        char buffer[kReadBufferSize];
        while (true) {
            const ssize_t bytes_read = read(watch_descriptor, buffer, sizeof(buffer));
            if (bytes_read <= 0) {
                break;
            }

            ssize_t offset = 0;
            while (offset + static_cast<ssize_t>(sizeof(inotify_event_header)) <= bytes_read) {
                auto *event = reinterpret_cast<inotify_event_header *>(buffer + offset);
                const ssize_t event_size =
                        static_cast<ssize_t>(sizeof(inotify_event_header)) + event->len;
                if (event_size <= 0 || offset + event_size > bytes_read) {
                    summary.invalid_count += 1;
                    break;
                }

                summary.raw_event_count += 1;
                // search_manager opens the directory inode itself, so the name field stays empty.
                // Named events belong to unrelated activity inside the package directory.
                if (event->len == 0) {
                    if ((event->mask & IN_OPEN) != 0) {
                        summary.directory_open_count += 1;
                    }
                    if ((event->mask & IN_ACCESS) != 0) {
                        summary.directory_access_count += 1;
                    }
                }

                offset += event_size;
            }
        }

        summary.detail = "directory IN_OPEN=" + std::to_string(summary.directory_open_count) +
                         " IN_ACCESS=" + std::to_string(summary.directory_access_count) +
                         " raw=" + std::to_string(summary.raw_event_count);
        return summary;
    }

    void reset_throne_hunt_watch(const int watch_descriptor) {
        if (watch_descriptor < 0) {
            return;
        }
        char buffer[kReadBufferSize];
        // Deliberately discard: the stimulus window is bounded in Kotlin, and draining here keeps
        // a stale event from being attributed to the next round.
        while (read(watch_descriptor, buffer, sizeof(buffer)) > 0) {
        }
    }

}  // namespace duckdetector::nativeroot
