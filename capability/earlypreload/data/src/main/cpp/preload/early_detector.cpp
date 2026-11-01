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

#include "preload/early_detector.h"

#include <android/log.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <mntent.h>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LOG_TAG "EarlyMountPreload"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace duckdetector::preload {

    namespace {

        constexpr std::int64_t kSecToNs = 1000000000LL;
        constexpr std::int64_t kValidContextThresholdNs = 5LL * kSecToNs;

        EarlyMountPreloadResult g_storedResult;
        bool g_hasRun = false;
        std::int64_t g_preloadTimestampNs = 0;

        std::int64_t realtime_coarse_now_ns() {
            struct timespec now{};
            clock_gettime(CLOCK_REALTIME_COARSE, &now);
            return (static_cast<std::int64_t>(now.tv_sec) * kSecToNs) + now.tv_nsec;
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
                        "FUTILE_HIDE|ns/mnt inode ctime observation: delta=" + std::to_string(delta) +
                        " ns|INFO"
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
                        "FUTILE_HIDE|mountinfo inode ctime observation: delta=" + std::to_string(delta) +
                        " ns|INFO"
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

        if (target == "/data/adb" || target.starts_with("/data/adb/")) {
            detected = true;
            result.mntStringsDetected = true;
            result.findings.push_back(
                    "MNT_STRINGS|Suspicious target path in mntent: " + target + "|DANGER"
            );
        }

        return detected;
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
