/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

#include "mount/detector_core.h"
#include "common/mount_id_observation.h"
#include "common/mount_artifact_markers.h"
#include "mount/detector_internal.h"
#include <android/log.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/stat.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unordered_set>
#include <utility>
#include <vector>

namespace duckdetector::mount::detail {

    void detect_mounts(
            MountSnapshot &snapshot,
            const std::vector<MountEntry> &mounts,
            std::unordered_set<std::string> &dedupe
    ) {
        snapshot.mountsReadable = !mounts.empty();
        snapshot.mountEntryCount = static_cast<int>(mounts.size());

        for (const MountEntry &entry: mounts) {
            const std::string lowerSource = lowercase_copy(entry.source);
            const std::string lowerTarget = lowercase_copy(entry.target);
            const std::string lowerFs = lowercase_copy(entry.fsType);
            const std::string lowerOptions = lowercase_copy(entry.options);

            const auto artifactLabels = common::mount_artifact_labels("", entry.target, entry.source);
            const auto hasLabel = [&](const std::string &label) {
                return std::find(artifactLabels.begin(), artifactLabels.end(), label) != artifactLabels.end();
            };
            if (hasLabel("Magisk") || hasLabel("data/adb") || hasLabel("ADB modules")) {
                snapshot.magiskMountDetected |= hasLabel("Magisk");
                snapshot.rootMountArtifactDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        "DANGER",
                        hasLabel("Magisk") ? "Magisk mounts" : "Root mount artifact",
                        entry.target,
                        entry.source + " -> " + entry.target + " (" + entry.fsType + ")"
                );
            }

            if (is_system_partition(entry.target)) {
                const bool isRw = starts_with(lowerOptions, "rw,") || lowerOptions == "rw";
                if (isRw) {
                    snapshot.systemRwDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "WARNING",
                            "System RW",
                            entry.target,
                            "Mount options: " + entry.options
                    );
                }

                if ((lowerFs == "overlay" || lowerFs == "overlayfs") &&
                    lowerTarget.find("/overlay/") == std::string::npos) {
                    snapshot.overlayMountDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "WARNING",
                            "Overlay mount",
                            entry.target,
                            entry.source + " -> " + entry.target + " (" + entry.fsType + ")"
                    );
                }

                if (lowerSource.find("/dev/block/loop") != std::string::npos ||
                    lowerSource.find("modules.img") != std::string::npos ||
                    lowerSource.find("overlayfs_loop") != std::string::npos) {
                    snapshot.loopDeviceDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "WARNING",
                            "Loop device mount",
                            entry.target,
                            entry.source + " -> " + entry.target
                    );
                }

                if (lowerSource.find("/dev/mapper/") == std::string::npos &&
                    lowerSource.find("/dev/block/dm-") == std::string::npos &&
                    lowerFs != "overlay" &&
                    lowerFs != "overlayfs") {

                    add_finding(
                            snapshot,
                            dedupe,
                            "RUNTIME",
                            "INFO",
                            "Mount source",
                            entry.target,
                            "Source=" + entry.source + ". A source pathname does not establish dm-verity state."
                    );
                }
            }

            if (lowerFs == "tmpfs" &&
                (lowerTarget == "/sbin" || lowerTarget == "/.magisk" ||
                 lowerTarget == "/patch_hw" || lowerTarget == "/dev/meta_hybird_mnt")) {
                add_finding(
                        snapshot,
                        dedupe,
                        "FILESYSTEM",
                        "INFO",
                        "Tmpfs mount",
                        entry.target,
                        entry.source + " -> " + entry.target + " (" + entry.options + ")"
                );
            }

            if (hasLabel("KernelSU") || hasLabel("APatch") || hasLabel("Magic mount")) {
                snapshot.ksuOverlayDetected |= hasLabel("KernelSU");
                snapshot.rootMountArtifactDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        "DANGER",
                        "Root manager mount source",
                        entry.target,
                        entry.source + " -> " + entry.target
                );
            }

            if (hasLabel("Magic mount")) {
                snapshot.metaHybridMountDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        "DANGER",
                        "Magic-mount source",
                        entry.target,
                        entry.source + " -> " + entry.target
                );
            }
        }
    }

    void detect_mountinfo(
            MountSnapshot &snapshot,
            const std::vector<MountInfoEntry> &entries,
            std::unordered_set<std::string> &dedupe
    ) {
        snapshot.mountInfoReadable = !entries.empty();
        snapshot.mountInfoEntryCount = static_cast<int>(entries.size());

        for (const MountInfoEntry &entry: entries) {
            auto rootLabels = common::mount_artifact_labels(entry.root, entry.target, entry.source);
            rootLabels.erase(std::remove(rootLabels.begin(), rootLabels.end(), "debug_ramdisk"), rootLabels.end());
            if (!rootLabels.empty()) {
                add_finding(
                        snapshot, dedupe, "CONSISTENCY", "DANGER", "Root mount artifact",
                        entry.target, "root=" + entry.root + ", source=" + entry.source
                );
            }
            const std::string optionalJoined = join_optional_fields(entry.optionalFields);
            const std::string lowerOptional = lowercase_copy(optionalJoined);
            const std::string lowerSuper = lowercase_copy(entry.superOptions);

            if (is_system_partition(entry.target) && entry.root != "/") {

                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "INFO",
                        "Mount root subset",
                        entry.target,
                        "root=" + entry.root + ", source=" + entry.source
                );
            }

            if (is_system_partition(entry.target) &&
                (lowerSuper.find("context=") != std::string::npos ||
                 lowerSuper.find("fscontext=") != std::string::npos ||
                 lowerSuper.find("defcontext=") != std::string::npos ||
                 lowerSuper.find("rootcontext=") != std::string::npos)) {

                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "INFO",
                        "SELinux mount context",
                        entry.target,
                        entry.superOptions
                );
            }

            if (entry.target == "/" && lowerOptional.find("shared:") == std::string::npos &&
                lowerOptional.find("master:") == std::string::npos &&
                lowerOptional.find("unbindable") == std::string::npos) {

                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "INFO",
                        "Root mount propagation",
                        "Private",
                        optionalJoined.empty()
                        ? "No shared/master propagation markers were present on the root mount."
                        : optionalJoined
                );
            }
        }

        const auto observations = common::observe_mount_id_discontinuities(entries);
        snapshot.mountIdLoopholeDetected = !observations.empty();
        for (const auto &observation: observations) {
            add_finding(
                    snapshot,
                    dedupe,
                    "CONSISTENCY",
                    "INFO",
                    "Mount ID discontinuity",
                    "Observed",
                    observation.detail()
            );
        }

#ifdef __NR_statx
        snapshot.statxSupported = is_statx_supported();

        struct StatxCheck {
            const char *path;
            const char *label;
        };
        static const std::array<StatxCheck, 4> kChecks = {{
                                                                  {"/data/data", "App data"},
                                                                  {"/system/bin", "System bin"},
                                                                  {"/system/lib64",
                                                                   "System lib64"},
                                                                  {"/vendor/bin", "Vendor bin"},
                                                          }};

        if (snapshot.statxSupported) {
            bool mountIdReturned = false;
            for (const StatxCheck &check: kChecks) {
                struct statx stx{};
                const int statxResult = static_cast<int>(
                        syscall(__NR_statx, AT_FDCWD, check.path, AT_NO_AUTOMOUNT,
                                STATX_BASIC_STATS | kStatxMountIdMask, &stx)
                );
                if (statxResult != 0 || (stx.stx_mask & kStatxMountIdMask) == 0) {
                    continue;
                }

                mountIdReturned = true;
                const bool mountRootFlagKnown =
                        (stx.stx_attributes_mask & kStatxMountRootMask) != 0;
                const bool isMountRoot =
                        mountRootFlagKnown && (stx.stx_attributes & kStatxMountRootMask) != 0;
                if (isMountRoot) {
                    snapshot.statxMountRootAttribute = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "INFO",
                            "statx mount root",
                            check.path,
                            std::string(check.label) +
                            " reports the VFS mount-root attribute; this is not an integrity violation."
                    );
                }

                // statx follows symlinks and resolves the active covering mount. A literal
                // mountpoint row (including a covered/stacked mount) is not its expected ID.
                const bool visibleId = std::any_of(entries.begin(), entries.end(), [&](const auto &entry) {
                    return static_cast<std::uint64_t>(entry.id) == stx.stx_mnt_id;
                });
                if (!visibleId && !entries.empty()) {
                    snapshot.statxMntIdMismatch = true;
                    add_finding(
                            snapshot, dedupe, "CONSISTENCY", "INFO",
                            "statx mount ID observation", check.path,
                            "statx=" + std::to_string(stx.stx_mnt_id) +
                            " was not in the earlier mountinfo capture. The captures are not atomic; "
                            "mount changes or incomplete visibility must be excluded before inferring tampering."
                    );
                }
            }
            snapshot.statxSupported = mountIdReturned;
        }
#else
        snapshot.statxSupported = false;
#endif
    }

}  // namespace duckdetector::mount::detail
