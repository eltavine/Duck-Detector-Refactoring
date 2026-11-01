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

    void detect_busybox(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    ) {
        static const std::array<const char *, 11> kBusyboxPaths = {
                "/system/xbin/busybox",
                "/system/bin/busybox",
                "/system/sd/xbin/busybox",
                "/vendor/bin/busybox",
                "/product/bin/busybox",
                "/sbin/busybox",
                "/data/local/xbin/busybox",
                "/data/local/bin/busybox",
                "/data/adb/magisk/busybox",
                "/data/adb/ksu/bin/busybox",
                "/data/adb/ap/bin/busybox",
        };

        for (const char *path: kBusyboxPaths) {
            const AccessResult access = check_access(path, false, snapshot);
            if (access == AccessResult::Exists) {
                snapshot.busyboxDetected = true;
                const bool rootPath = common::mount_path_is_within(path, "/data/adb");
                snapshot.dataAdbDetected |= rootPath;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        rootPath ? "DANGER" : "INFO",
                        "Busybox binary",
                        "Present",
                        path
                );
            }
        }
    }

    void detect_root_data_paths(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    ) {
        const AccessResult dataAdbAccess = check_access("/data/adb", true, snapshot);
        if (dataAdbAccess == AccessResult::PermissionDenied) {
            add_finding(
                    snapshot,
                    dedupe,
                    "CONSISTENCY",
                    "INFO",
                    "/data/adb access",
                    "Restricted",
                    "The app could not read /data/adb directly, which is normal without root."
            );
            return;
        }

        struct RootPathSpec {
            const char *path;
            const char *label;
            bool isDirectory;
        };
        static const std::array<RootPathSpec, 9> kRootPaths = {{
                                                                       {"/data/adb/magisk",
                                                                        "Magisk data directory",
                                                                        true},
                                                                       {"/data/adb/magisk.db",
                                                                        "Magisk database",
                                                                        false},
                                                                       {"/data/adb/ksu",
                                                                        "KernelSU data directory",
                                                                        true},
                                                                       {"/data/adb/ksud",
                                                                        "KernelSU daemon",
                                                                        false},
                                                                       {"/data/adb/ap",
                                                                        "APatch data directory",
                                                                        true},
                                                                       {"/data/adb/apd",
                                                                        "APatch daemon", false},
                                                                       {"/data/adb/modules",
                                                                        "Root modules directory",
                                                                        true},
                                                                       {"/data/adb/service.d",
                                                                        "Root service scripts",
                                                                        true},
                                                                       {"/data/adb/post-fs-data.d",
                                                                        "Post-fs-data scripts",
                                                                        true},
                                                               }};

        for (const RootPathSpec &spec: kRootPaths) {
            if (check_access(spec.path, spec.isDirectory, snapshot) == AccessResult::Exists) {
                snapshot.dataAdbDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        "DANGER",
                        spec.label,
                        "Present",
                        spec.path
                );
            }
        }
    }

    void detect_debug_ramdisk(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    ) {
        struct DebugSpec {
            const char *path;
            const char *label;
            bool isDirectory;
            const char *severity;
        };

        static const std::array<DebugSpec, 4> kSpecs = {{
                                                                {"/debug_ramdisk/adb_debug.prop",
                                                                 "adb_debug.prop", false,
                                                                 "INFO"},
                                                                {"/debug_ramdisk/userdebug_plat_sepolicy.cil",
                                                                 "userdebug sepolicy", false,
                                                                 "INFO"},
                                                                {"/debug_ramdisk/force_debuggable",
                                                                 "force_debuggable", false,
                                                                 "INFO"},
                                                                {"/debug_ramdisk/force_adb",
                                                                 "force_adb", false, "INFO"},
                                                        }};

        for (const DebugSpec &spec: kSpecs) {
            if (check_access(spec.path, spec.isDirectory, snapshot) == AccessResult::Exists) {
                snapshot.debugRamdiskDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        spec.severity,
                        spec.label,
                        "Present",
                        spec.path
                );
            }
        }
    }

    void detect_hybrid_paths(
            MountSnapshot &snapshot,
            std::unordered_set<std::string> &dedupe
    ) {
        struct HybridSpec {
            const char *path;
            const char *label;
            bool isDirectory;
            bool metaHybrid;
        };
        static const std::array<HybridSpec, 4> kSpecs = {{
                                                                 {"/dev/meta_hybird_mnt",
                                                                  "Meta hybrid device", false,
                                                                  false},
                                                                 {"/patch_hw",
                                                                  "Meta-Hybrid patch path",
                                                                  true, true},
                                                                 {"/.magic_mount",
                                                                  "Magic mount workdir", true,
                                                                  true},
                                                                 {"/data/adb/modules/.core",
                                                                  "Root core modules", true,
                                                                  true},
                                                         }};

        for (const HybridSpec &spec: kSpecs) {
            if (check_access(spec.path, spec.isDirectory, snapshot) == AccessResult::Exists) {
                const bool rootPath = common::mount_path_is_within(spec.path, "/data/adb");
                snapshot.dataAdbDetected |= rootPath;
                add_finding(
                        snapshot,
                        dedupe,
                        "ARTIFACTS",
                        rootPath ? "DANGER" : "INFO",
                        spec.label,
                        "Present",
                        spec.path
                );
            }
        }
    }

    void detect_maps(
            MountSnapshot &snapshot,
            const std::string &mapsRaw,
            std::unordered_set<std::string> &dedupe
    ) {
        snapshot.mapsReadable = !mapsRaw.empty();
        if (!snapshot.mapsReadable) {
            return;
        }

        static const std::array<std::pair<const char *, const char *>, 5> kPatterns = {{
                                                                                               {"libzygisk.so",
                                                                                                "Zygisk library"},
                                                                                               {"libriru.so",
                                                                                                "Riru library"},
                                                                                               {"libriru_",
                                                                                                "Riru module library"},
                                                                                               {"/.magisk/",
                                                                                                "Magisk hidden memory path"},
                                                                                               {"/sbin/.magisk",
                                                                                                "Magisk sbin memory path"},
                                                                                       }};

        std::istringstream stream(mapsRaw);
        std::string line;
        while (std::getline(stream, line)) {
            snapshot.mapLineCount += 1;
            for (const auto &pattern: kPatterns) {
                if (line.find(pattern.first) != std::string::npos) {
                    snapshot.zygiskCacheDetected = true;
                    const size_t pathStart = line.rfind('/');
                    const std::string display =
                            pathStart != std::string::npos ? line.substr(pathStart) : line;
                    add_finding(
                            snapshot,
                            dedupe,
                            "ARTIFACTS",
                            "DANGER",
                            pattern.second,
                            "Mapped",
                            display
                    );
                }
            }
        }
    }

}  // namespace duckdetector::mount::detail
