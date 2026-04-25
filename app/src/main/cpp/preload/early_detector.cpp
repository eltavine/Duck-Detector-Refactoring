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

#include "preload/early_detector.h"

#include <android/log.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <mntent.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <vector>

#define LOG_TAG "EarlyMountPreload"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace duckdetector::preload {

    namespace {

        constexpr std::int64_t kSecToNs = 1000000000LL;
        constexpr std::int64_t kValidContextThresholdNs = 5LL * kSecToNs;

        struct MountInfoEntry {
            int id = 0;
            int parentId = 0;
            unsigned int major = 0;
            unsigned int minor = 0;
            std::string root;
            std::string target;
            std::string vfsOptions;
            int masterGroup = 0;
            std::string fsType;
            std::string source;
            std::string superOptions;
        };

        struct MountIdGapSummary {
            bool reachedDataUserBoundary = false;
            int missingCount = 0;
            int firstMissingStart = 0;
            int firstMissingEnd = 0;
        };

        EarlyMountPreloadResult g_storedResult;
        bool g_hasRun = false;
        std::int64_t g_preloadTimestampNs = 0;

        std::int64_t realtime_coarse_now_ns() {
            struct timespec now{};
            clock_gettime(CLOCK_REALTIME_COARSE, &now);
            return (static_cast<std::int64_t>(now.tv_sec) * kSecToNs) + now.tv_nsec;
        }

        bool parse_mountinfo_line(const std::string &line, MountInfoEntry &entry) {
            std::istringstream iss(line);
            std::string devStr;

            if (!(iss >> entry.id >> entry.parentId >> devStr >> entry.root >> entry.target
                      >> entry.vfsOptions)) {
                return false;
            }

            const std::size_t colonPos = devStr.find(':');
            if (colonPos == std::string::npos) {
                return false;
            }
            entry.major = static_cast<unsigned int>(std::stoul(devStr.substr(0, colonPos)));
            entry.minor = static_cast<unsigned int>(std::stoul(devStr.substr(colonPos + 1)));

            entry.masterGroup = 0;
            std::string token;
            while (iss >> token && token != "-") {
                if (token.starts_with("shared:") || token.starts_with("master:")) {
                    const std::size_t fieldColon = token.find(':');
                    if (fieldColon != std::string::npos) {
                        entry.masterGroup = std::stoi(token.substr(fieldColon + 1));
                    }
                }
            }

            if (!(iss >> entry.fsType >> entry.source)) {
                return false;
            }
            std::getline(iss, entry.superOptions);
            return true;
        }

        std::vector<MountInfoEntry> parse_mountinfo() {
            std::vector<MountInfoEntry> entries;
            std::ifstream file("/proc/self/mountinfo");
            std::string line;
            while (std::getline(file, line)) {
                MountInfoEntry entry;
                if (parse_mountinfo_line(line, entry)) {
                    entries.push_back(entry);
                }
            }
            return entries;
        }

        bool get_mnt_strings(std::string &outSource, std::string &outTarget, std::string &outFs) {
            constexpr uintptr_t kMask = static_cast<uintptr_t>(0xffa13e300ULL);
            int pipes[2];
            if (pipe(pipes) == -1) {
                LOGE("pipe() failed: %s", strerror(errno));
                return false;
            }

            const pid_t pid = static_cast<pid_t>(syscall(SYS_clone, SIGCHLD, 0));
            if (pid < 0) {
                LOGE("clone() failed: %s", strerror(errno));
                close(pipes[0]);
                close(pipes[1]);
                return false;
            }

            if (pid == 0) {
                close(pipes[0]);
                FILE *file = setmntent("/proc/self/mounts", "r");
                if (file == nullptr) {
                    uintptr_t value = kMask;
                    write(pipes[1], &value, sizeof(value));
                    close(pipes[1]);
                    _Exit(1);
                }

                struct mntent *entry = nullptr;
                while ((entry = getmntent(file)) != nullptr) {
                }

                uintptr_t value = kMask;
                if (entry != nullptr) {
                    value = reinterpret_cast<uintptr_t>(entry + 1) ^ kMask;
                }

                endmntent(file);
                write(pipes[1], &value, sizeof(value));
                close(pipes[1]);
                _Exit(0);
            }

            close(pipes[1]);
            uintptr_t value = kMask;
            read(pipes[0], &value, sizeof(value));
            close(pipes[0]);

            int status = 0;
            waitpid(pid, &status, 0);
            value ^= kMask;
            if (value == 0) {
                LOGE("Failed to get mntent_strings buffer");
                return false;
            }

            FILE *file = setmntent("/proc/self/mounts", "r");
            if (file == nullptr) {
                return false;
            }

            struct mntent *lastEntry = nullptr;
            struct mntent *entry = nullptr;
            while ((entry = getmntent(file)) != nullptr) {
                lastEntry = entry;
            }

            if (lastEntry != nullptr) {
                outSource = lastEntry->mnt_fsname ? lastEntry->mnt_fsname : "";
                outTarget = lastEntry->mnt_dir ? lastEntry->mnt_dir : "";
                outFs = lastEntry->mnt_type ? lastEntry->mnt_type : "";
            }

            endmntent(file);
            return lastEntry != nullptr;
        }

        bool is_path_or_child_of(const std::string &target, const std::string &prefix) {
            return target == prefix ||
                   (target.size() > prefix.size() &&
                    target.compare(0, prefix.size(), prefix) == 0 &&
                    target[prefix.size()] == '/');
        }

        bool is_platform_tmpfs_namespace_target(const std::string &target) {
            static const char *const kNamespaces[] = {
                    "/dev",
                    "/mnt",
                    "/storage",
                    "/apex",
                    "/linkerconfig",
                    "/sys",
                    "/tmp",
                    "/data_mirror",
                    "/debug_ramdisk",
            };

            for (const char *prefix: kNamespaces) {
                if (is_path_or_child_of(target, prefix)) {
                    return true;
                }
            }
            return false;
        }

        bool find_mount_minor_for_target(
                const std::vector<MountInfoEntry> &mounts,
                const std::string &target,
                unsigned int &outMinor
        ) {
            for (const auto &mount: mounts) {
                if (mount.target == target) {
                    outMinor = mount.minor;
                    return true;
                }
            }
            return false;
        }

        bool summarize_data_mirror_mount_id_gap(
                const std::vector<MountInfoEntry> &mounts,
                std::size_t dataMirrorIndex,
                MountIdGapSummary &summary
        ) {
            if (dataMirrorIndex == 0 || dataMirrorIndex >= mounts.size()) {
                return false;
            }

            int currentId = mounts[dataMirrorIndex].id;
            for (int scanIndex = static_cast<int>(dataMirrorIndex) - 1;
                 scanIndex >= 0 && currentId - mounts[static_cast<std::size_t>(scanIndex)].id < 10;
                 --scanIndex) {
                const auto &candidate = mounts[static_cast<std::size_t>(scanIndex)];
                if (candidate.id == currentId - 1) {
                    currentId = candidate.id;
                    if (candidate.target.starts_with("/data/user")) {
                        summary.reachedDataUserBoundary = true;
                        break;
                    }
                    continue;
                }

                const int gapSize = currentId - candidate.id - 1;
                if (gapSize <= 0) {
                    continue;
                }

                if (summary.firstMissingStart == 0) {
                    summary.firstMissingStart = candidate.id + 1;
                    summary.firstMissingEnd = currentId - 1;
                }
                summary.missingCount += gapSize;
                currentId = candidate.id;

                if (candidate.target.starts_with("/data/user")) {
                    summary.reachedDataUserBoundary = true;
                    break;
                }
            }

            // Single and double missing IDs show up on some stock devices from transient
            // teardown or short-lived remount churn; only treat the /data_mirror chain as
            // anomalous once the local walk shows a larger multi-ID gap and we reached the
            // expected /data/user boundary.
            return summary.reachedDataUserBoundary && summary.missingCount >= 3;
        }

    }  // namespace

    bool detect_futile_hide(EarlyMountPreloadResult &result) {
        struct timespec now{};
        clock_gettime(CLOCK_REALTIME_COARSE, &now);
        usleep(100);

        bool detected = false;

        struct stat nsStat{};
        if (fstatat(AT_FDCWD, "/proc/self/ns/mnt", &nsStat, AT_SYMLINK_NOFOLLOW) == 0) {
            const std::int64_t delta =
                    ((static_cast<std::int64_t>(nsStat.st_ctim.tv_sec) - now.tv_sec) * kSecToNs) +
                    (nsStat.st_ctim.tv_nsec - now.tv_nsec);
            result.nsMntCtimeDeltaNs = delta;
            if (delta < -kSecToNs) {
                detected = true;
                result.futileHideDetected = true;
                result.findings.push_back(
                        "FUTILE_HIDE|ns/mnt ctime anomaly: delta=" + std::to_string(delta) +
                        " ns|DANGER"
                );
            }
        }

        struct stat mountInfoStat{};
        if (stat("/proc/self/mountinfo", &mountInfoStat) == 0) {
            const std::int64_t delta =
                    ((static_cast<std::int64_t>(mountInfoStat.st_ctim.tv_sec) - now.tv_sec) *
                     kSecToNs) +
                    (mountInfoStat.st_ctim.tv_nsec - now.tv_nsec);
            result.mountInfoCtimeDeltaNs = delta;
            if (delta < -kSecToNs) {
                detected = true;
                result.futileHideDetected = true;
                result.findings.push_back(
                        "FUTILE_HIDE|mountinfo ctime anomaly: delta=" + std::to_string(delta) +
                        " ns|DANGER"
                );
            }
        }

        return detected;
    }

    bool detect_mnt_strings_anomaly(EarlyMountPreloadResult &result) {
        std::string source;
        std::string target;
        std::string fs;
        if (!get_mnt_strings(source, target, fs)) {
            return false;
        }

        result.mntStringsSource = source;
        result.mntStringsTarget = target;
        result.mntStringsFs = fs;

        bool detected = false;
        if (source == "KSU" || source == "magisk" || source == "APatch") {
            detected = true;
            result.mntStringsDetected = true;
            result.findings.push_back(
                    "MNT_STRINGS|Suspicious source name in mntent: " + source + "|DANGER"
            );
        }

        if (target.starts_with("/data/adb")) {
            detected = true;
            result.mntStringsDetected = true;
            result.findings.push_back(
                    "MNT_STRINGS|Suspicious target path in mntent: " + target + "|DANGER"
            );
        }

        return detected;
    }

    bool detect_mount_id_loophole(EarlyMountPreloadResult &result) {
        const auto mounts = parse_mountinfo();
        bool detected = false;

        for (std::size_t index = 0; index < mounts.size(); ++index) {
            const auto &mount = mounts[index];
            if (mount.target == "/apex/com.android.art" && index + 1 < mounts.size()) {
                const auto &next = mounts[index + 1];
                if (next.id > mount.id + 1) {
                    detected = true;
                    result.mountIdGapDetected = true;
                    result.findings.push_back(
                            "MOUNT_ID_GAP|Gap after /apex/com.android.art: expected " +
                            std::to_string(mount.id + 1) + ", got " + std::to_string(next.id) +
                            "|DANGER"
                    );
                }
            }

            if (mount.target == "/data_mirror") {
                MountIdGapSummary summary;
                if (summarize_data_mirror_mount_id_gap(mounts, index, summary)) {
                    detected = true;
                    result.mountIdGapDetected = true;
                    result.findings.push_back(
                            "MOUNT_ID_GAP|Missing " + std::to_string(summary.missingCount) +
                            " mount IDs before /data_mirror (first gap " +
                            std::to_string(summary.firstMissingStart) + "-" +
                            std::to_string(summary.firstMissingEnd) + ")|DANGER"
                    );
                }
                break;
            }
        }

        return detected;
    }

    bool detect_minor_dev_gap(EarlyMountPreloadResult &result) {
        const auto mounts = parse_mountinfo();
        unsigned int devMinor = 0;
        unsigned int sysMinor = 0;
        if (!find_mount_minor_for_target(mounts, "/dev", devMinor) ||
            !find_mount_minor_for_target(mounts, "/sys", sysMinor) ||
            sysMinor <= devMinor) {
            return false;
        }

        std::vector<MountInfoEntry> tmpfsMounts;
        for (const auto &mount: mounts) {
            if (mount.major == 0 && mount.root == "/" && mount.fsType == "tmpfs") {
                tmpfsMounts.push_back(mount);
            }
        }

        std::sort(
                tmpfsMounts.begin(),
                tmpfsMounts.end(),
                [](const MountInfoEntry &left, const MountInfoEntry &right) {
                    return left.minor < right.minor;
                }
        );

        unsigned int lastMinor = devMinor;
        for (const auto &mount: tmpfsMounts) {
            if (mount.minor <= devMinor) {
                continue;
            }
            if (mount.minor >= sysMinor) {
                break;
            }

            if (is_platform_tmpfs_namespace_target(mount.target)) {
                lastMinor = mount.minor;
                continue;
            }

            result.minorDevGapDetected = true;
            if (mount.minor != lastMinor + 1) {
                result.findings.push_back(
                        "MINOR_DEV_GAP|Expected minor " + std::to_string(lastMinor + 1) +
                        ", got " + std::to_string(mount.minor) + " at " + mount.target + "|WARNING"
                );
            } else {
                result.findings.push_back(
                        "MINOR_DEV_GAP|Unexpected tmpfs target before /sys: " + mount.target +
                        " (minor " + std::to_string(mount.minor) + ")|WARNING"
                );
            }
            return true;
        }

        return false;
    }

    bool detect_peer_group_gap(EarlyMountPreloadResult &result) {
        const auto mounts = parse_mountinfo();
        std::vector<bool> peerGroups;
        for (const auto &mount: mounts) {
            if (mount.masterGroup > 0) {
                if (peerGroups.size() < static_cast<std::size_t>(mount.masterGroup)) {
                    peerGroups.resize(static_cast<std::size_t>(mount.masterGroup), false);
                }
                peerGroups[static_cast<std::size_t>(mount.masterGroup - 1)] = true;
            }
        }

        constexpr int kAllowedGaps = 3;
        int gapCount = 0;
        for (bool present: peerGroups) {
            if (!present) {
                ++gapCount;
            }
        }

        if (gapCount > kAllowedGaps) {
            result.peerGroupGapDetected = true;
            result.findings.push_back(
                    "PEER_GROUP_GAP|Found " + std::to_string(gapCount) + " gaps (allowed " +
                    std::to_string(kAllowedGaps) + ")|WARNING"
            );
            return true;
        }

        return false;
    }

    bool is_preload_context_valid() {
        if (!g_hasRun) {
            return false;
        }
        return (realtime_coarse_now_ns() - g_preloadTimestampNs) < kValidContextThresholdNs;
    }

    EarlyMountPreloadResult run_early_detection() {
        EarlyMountPreloadResult result;
        g_preloadTimestampNs = realtime_coarse_now_ns();

        bool detected = false;
        detected |= detect_futile_hide(result);
        detected |= detect_mnt_strings_anomaly(result);
        detected |= detect_mount_id_loophole(result);
        detected |= detect_minor_dev_gap(result);
        detected |= detect_peer_group_gap(result);
        result.detected = detected;

        std::string methods;
        if (result.futileHideDetected) {
            methods += methods.empty() ? "FutileHide" : ", FutileHide";
        }
        if (result.mntStringsDetected) {
            methods += methods.empty() ? "MntStrings" : ", MntStrings";
        }
        if (result.mountIdGapDetected) {
            methods += methods.empty() ? "MountIdGap" : ", MountIdGap";
        }
        if (result.minorDevGapDetected) {
            methods += methods.empty() ? "MinorDevGap" : ", MinorDevGap";
        }
        if (result.peerGroupGapDetected) {
            methods += methods.empty() ? "PeerGroupGap" : ", PeerGroupGap";
        }

        result.detectionMethod = methods.empty() ? "None" : methods;
        result.details = detected
                         ? "Early mount preload detected: " + result.detectionMethod
                         : "No startup preload anomaly found";

        g_storedResult = result;
        g_hasRun = true;
        return result;
    }

    const EarlyMountPreloadResult *get_stored_result() {
        return g_hasRun ? &g_storedResult : nullptr;
    }

    bool has_early_detection_run() {
        return g_hasRun;
    }

    void reset_early_detection() {
        g_storedResult = EarlyMountPreloadResult{};
        g_hasRun = false;
        g_preloadTimestampNs = 0;
    }

}  // namespace duckdetector::preload
