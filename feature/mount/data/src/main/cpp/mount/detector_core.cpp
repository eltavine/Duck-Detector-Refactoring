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

namespace duckdetector::mount {

    using namespace detail;

    MountSnapshot collect_snapshot(const std::string &externalStorageRoot) {
        MountSnapshot snapshot;
        std::unordered_set<std::string> dedupe;

        bool mountsReadable = false;
        bool mountInfoReadable = false;
        bool mapsReadable = false;

        const std::string mountsRaw = read_file_direct("/proc/self/mounts", 131072,
                                                       &mountsReadable);
        const std::string mountInfoRaw = read_file_direct("/proc/self/mountinfo", 196608,
                                                          &mountInfoReadable);
        const std::string mapsRaw = read_file_direct("/proc/self/maps", 196608, &mapsReadable);

        const std::vector<MountEntry> mounts = parse_mounts(mountsRaw);
        bool mountInfoComplete = false;
        const std::vector<MountInfoEntry> mountInfo = parse_mount_info(mountInfoRaw, &mountInfoComplete);

        snapshot.mountsReadable = mountsReadable && !mounts.empty();
        snapshot.mountInfoReadable = mountInfoReadable && !mountInfo.empty();
        snapshot.mapsReadable = mapsReadable && !mapsRaw.empty();

        detect_busybox(snapshot, dedupe);
        detect_root_data_paths(snapshot, dedupe);
        detect_debug_ramdisk(snapshot, dedupe);
        detect_hybrid_paths(snapshot, dedupe);
        detect_maps(snapshot, mapsRaw, dedupe);
        detect_mounts(snapshot, mounts, dedupe);
        detect_mountinfo(snapshot, mountInfo, dedupe);
        snapshot.anonymousDevices = observe_anonymous_devices(
                mountInfo, mountInfoReadable && mountInfoComplete, externalStorageRoot);
        detect_namespace(snapshot, dedupe);
        detect_filesystems(snapshot, mounts, dedupe);
        detect_inconsistent_mount(snapshot, mounts, dedupe);

        return snapshot;
    }

    std::string encode_snapshot(const MountSnapshot &snapshot) {
        auto flag = [](bool value) -> const char * {
            return value ? "1" : "0";
        };

        std::ostringstream out;
        out << "ANON_DEVICE_STATE=" << anonymous_device_state_key(snapshot.anonymousDevices.state) << '\n';
        out << "ANON_DEVICE_DETAIL=" << sanitize_field(snapshot.anonymousDevices.detail) << '\n';
        out << "AVAILABLE=" << flag(snapshot.available) << '\n';
        out << "MOUNTS_READABLE=" << flag(snapshot.mountsReadable) << '\n';
        out << "MOUNTINFO_READABLE=" << flag(snapshot.mountInfoReadable) << '\n';
        out << "MAPS_READABLE=" << flag(snapshot.mapsReadable) << '\n';
        out << "FILESYSTEMS_READABLE=" << flag(snapshot.filesystemsReadable) << '\n';
        out << "INIT_NAMESPACE_READABLE=" << flag(snapshot.initNamespaceReadable) << '\n';
        out << "STATX_SUPPORTED=" << flag(snapshot.statxSupported) << '\n';
        out << "PERMISSION_TOTAL=" << snapshot.permissionTotal << '\n';
        out << "PERMISSION_DENIED=" << snapshot.permissionDenied << '\n';
        out << "PERMISSION_ACCESSIBLE=" << snapshot.permissionAccessible << '\n';
        out << "MOUNT_ENTRY_COUNT=" << snapshot.mountEntryCount << '\n';
        out << "MOUNTINFO_ENTRY_COUNT=" << snapshot.mountInfoEntryCount << '\n';
        out << "MAP_LINE_COUNT=" << snapshot.mapLineCount << '\n';
        out << "BUSYBOX=" << flag(snapshot.busyboxDetected) << '\n';
        out << "ROOT_MOUNT_ARTIFACT=" << flag(snapshot.rootMountArtifactDetected) << '\n';
        out << "MAGISK_MOUNT=" << flag(snapshot.magiskMountDetected) << '\n';
        out << "ZYGISK_CACHE=" << flag(snapshot.zygiskCacheDetected) << '\n';
        out << "SYSTEM_RW=" << flag(snapshot.systemRwDetected) << '\n';
        out << "OVERLAY_MOUNT=" << flag(snapshot.overlayMountDetected) << '\n';
        out << "NAMESPACE_ANOMALY=" << flag(snapshot.namespaceAnomalyDetected) << '\n';
        out << "DATA_ADB=" << flag(snapshot.dataAdbDetected) << '\n';
        out << "DEBUG_RAMDISK=" << flag(snapshot.debugRamdiskDetected) << '\n';
        out << "HYBRID_MOUNT=" << flag(snapshot.hybridMountDetected) << '\n';
        out << "META_HYBRID_MOUNT=" << flag(snapshot.metaHybridMountDetected) << '\n';
        out << "SUSPICIOUS_TMPFS=" << flag(snapshot.suspiciousTmpfsDetected) << '\n';
        out << "KSU_OVERLAY=" << flag(snapshot.ksuOverlayDetected) << '\n';
        out << "LOOP_DEVICE=" << flag(snapshot.loopDeviceDetected) << '\n';
        out << "DM_VERITY_BYPASS=" << flag(snapshot.dmVerityBypassDetected) << '\n';
        out << "MOUNT_PROPAGATION=" << flag(snapshot.mountPropagationAnomaly) << '\n';
        out << "INCONSISTENT_MOUNT=" << flag(snapshot.inconsistentMountDetected) << '\n';
        out << "MOUNT_ID_LOOPHOLE=" << flag(snapshot.mountIdLoopholeDetected) << '\n';
        out << "FUTILE_HIDE=" << flag(snapshot.futileHideDetected) << '\n';
        out << "STATX_MNT_ID_MISMATCH=" << flag(snapshot.statxMntIdMismatch) << '\n';
        out << "BIND_MOUNT_DETECTED=" << flag(snapshot.bindMountDetected) << '\n';
        out << "MOUNT_OPTIONS_ANOMALY=" << flag(snapshot.mountOptionsAnomaly) << '\n';
        out << "STATX_MOUNT_ROOT_ANOMALY=" << flag(snapshot.statxMountRootAnomaly) << '\n';
        out << "STATX_MOUNT_ROOT_ATTRIBUTE=" << flag(snapshot.statxMountRootAttribute) << '\n';
        out << "OVERLAYFS_KERNEL_SUPPORT=" << flag(snapshot.overlayfsKernelSupport) << '\n';
        out << "SYSTEM_FS_TYPE_ANOMALY=" << flag(snapshot.systemFsTypeAnomaly) << '\n';
        out << "TMPFS_SIZE_ANOMALY=" << flag(snapshot.tmpfsSizeAnomaly) << '\n';

        for (const MountFindingRecord &finding: snapshot.findings) {
            out << "FINDING="
                << sanitize_field(finding.group) << '\t'
                << sanitize_field(finding.severity) << '\t'
                << sanitize_field(finding.label) << '\t'
                << sanitize_field(finding.value) << '\t'
                << sanitize_field(finding.detail) << '\n';
        }

        return out.str();
    }

}  // namespace duckdetector::mount
