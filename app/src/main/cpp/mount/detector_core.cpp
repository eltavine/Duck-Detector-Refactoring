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

#include "mount/detector_core.h"

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

#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif

#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xE0F5E1E2
#endif

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

namespace duckdetector::mount {
    namespace {

        constexpr char kLogTag[] = "DuckMount";

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, kLogTag, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, kLogTag, __VA_ARGS__)

        struct MountEntry {
            std::string source;
            std::string target;
            std::string fsType;
            std::string options;
        };

        struct MountInfoEntry {
            int id = 0;
            int parentId = 0;
            unsigned int major = 0;
            unsigned int minor = 0;
            std::string root;
            std::string target;
            std::string options;
            std::vector<std::string> optionalFields;
            std::string fsType;
            std::string source;
            std::string superOptions;
        };

        enum class AccessResult {
            Exists,
            NotExists,
            PermissionDenied,
        };

#ifdef __NR_statx
        enum class StatxAvailability : int {
            Unknown = 0,
            Supported = 1,
            Unsupported = 2,
        };

        constexpr unsigned int kStatxMountIdMask = 0x00001000;
        constexpr unsigned int kStatxMountRootMask = 0x00002000;
        std::atomic<int> g_statxAvailability{
                static_cast<int>(StatxAvailability::Unknown)};
#endif

        int syscall_open_readonly(const char *path, int flags = O_RDONLY | O_CLOEXEC) {
            return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags));
        }

        ssize_t syscall_read_fd(int fd, void *buffer, size_t count) {
            return syscall(__NR_read, fd, buffer, count);
        }

        int syscall_close_fd(int fd) {
            return static_cast<int>(syscall(__NR_close, fd));
        }

        int syscall_stat_path(const char *path, struct stat *st) {
#if defined(__aarch64__) || defined(__x86_64__)
            return static_cast<int>(syscall(__NR_newfstatat, AT_FDCWD, path, st, 0));
#elif defined(__arm__) || defined(__i386__)
            return static_cast<int>(syscall(__NR_fstatat64, AT_FDCWD, path, st, 0));
#else
            return stat(path, st);
#endif
        }

        ssize_t syscall_readlink_path(const char *path, char *buffer, size_t bufferSize) {
            return syscall(__NR_readlinkat, AT_FDCWD, path, buffer, bufferSize);
        }

#ifdef __NR_statx

        bool is_statx_supported() {
            const auto cached = static_cast<StatxAvailability>(
                    g_statxAvailability.load(std::memory_order_acquire));
            if (cached != StatxAvailability::Unknown) {
                return cached == StatxAvailability::Supported;
            }

            StatxAvailability resolved = StatxAvailability::Unsupported;
            const pid_t pid = fork();
            if (pid < 0) {
                LOGI("statx support probe fork failed: %s", strerror(errno));
            } else if (pid == 0) {
                struct statx stx{};
                errno = 0;
                const long result = syscall(
                        __NR_statx,
                        AT_FDCWD,
                        "/",
                        AT_NO_AUTOMOUNT,
                        STATX_BASIC_STATS,
                        &stx);
                if (result == 0) {
                    _exit(0);
                }
                _exit(errno == ENOSYS ? 1 : 0);
            } else {
                int status = 0;
                if (waitpid(pid, &status, 0) < 0) {
                    LOGI("statx support probe waitpid failed: %s", strerror(errno));
                } else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
                    LOGI("statx support probe blocked by seccomp; disabling statx probes");
                } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    resolved = StatxAvailability::Supported;
                } else {
                    LOGI("statx support probe reported unsupported or inconclusive status=%d",
                         status);
                }
            }

            g_statxAvailability.store(
                    static_cast<int>(resolved),
                    std::memory_order_release);
            return resolved == StatxAvailability::Supported;
        }

#endif

        std::string trim_copy(std::string value) {
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
                value.erase(value.begin());
            }
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
                value.pop_back();
            }
            return value;
        }

        std::string lowercase_copy(std::string value) {
            std::transform(
                    value.begin(),
                    value.end(),
                    value.begin(),
                    [](unsigned char ch) {
                        return static_cast<char>(std::tolower(ch));
                    }
            );
            return value;
        }

        std::string sanitize_field(std::string value) {
            for (char &ch: value) {
                if (ch == '\n' || ch == '\r' || ch == '\t') {
                    ch = ' ';
                }
            }
            return trim_copy(value);
        }

        bool contains_ignore_case(const std::string &haystack, const std::string &needle) {
            return lowercase_copy(haystack).find(lowercase_copy(needle)) != std::string::npos;
        }

        std::string read_file_direct(const char *path, size_t maxSize, bool *readable = nullptr) {
            if (readable != nullptr) {
                *readable = false;
            }

            const int fd = syscall_open_readonly(path);
            if (fd < 0) {
                return "";
            }

            std::string content;
            content.resize(maxSize);
            const ssize_t bytesRead = syscall_read_fd(fd, content.data(), maxSize - 1);
            syscall_close_fd(fd);

            if (bytesRead <= 0) {
                return "";
            }

            content.resize(static_cast<size_t>(bytesRead));
            if (readable != nullptr) {
                *readable = true;
            }
            return content;
        }

        std::string read_namespace_link(const char *path, bool *readable = nullptr) {
            if (readable != nullptr) {
                *readable = false;
            }

            std::array<char, 256> buffer{};
            const ssize_t length = syscall_readlink_path(path, buffer.data(), buffer.size() - 1);
            if (length <= 0) {
                return "";
            }
            buffer[static_cast<size_t>(length)] = '\0';
            if (readable != nullptr) {
                *readable = true;
            }
            return std::string(buffer.data());
        }

        AccessResult check_access(
                const char *path,
                bool expectDirectory,
                MountSnapshot &snapshot
        ) {
            snapshot.permissionTotal += 1;

            struct stat st{};
            if (syscall_stat_path(path, &st) == 0) {
                snapshot.permissionAccessible += 1;
                if (expectDirectory && !S_ISDIR(st.st_mode)) {
                    return AccessResult::NotExists;
                }
                return AccessResult::Exists;
            }

            if (errno == EACCES || errno == EPERM) {
                snapshot.permissionDenied += 1;
                return AccessResult::PermissionDenied;
            }

            snapshot.permissionAccessible += 1;
            return AccessResult::NotExists;
        }

        std::vector<MountEntry> parse_mounts(const std::string &raw) {
            std::vector<MountEntry> entries;
            std::istringstream stream(raw);
            std::string line;
            while (std::getline(stream, line)) {
                MountEntry entry;
                std::istringstream lineStream(line);
                if (!(lineStream >> entry.source >> entry.target >> entry.fsType
                                 >> entry.options)) {
                    continue;
                }
                entries.push_back(entry);
            }
            return entries;
        }

        bool parse_mount_info_line(const std::string &line, MountInfoEntry &entry) {
            const size_t separator = line.find(" - ");
            if (separator == std::string::npos) {
                return false;
            }

            std::istringstream left(line.substr(0, separator));
            std::string majorMinor;
            if (!(left >> entry.id >> entry.parentId >> majorMinor >> entry.root >> entry.target
                       >> entry.options)) {
                return false;
            }
            if (std::sscanf(majorMinor.c_str(), "%u:%u", &entry.major, &entry.minor) != 2) {
                return false;
            }

            std::string optional;
            while (left >> optional) {
                entry.optionalFields.push_back(optional);
            }

            std::istringstream right(line.substr(separator + 3));
            if (!(right >> entry.fsType >> entry.source)) {
                return false;
            }
            std::getline(right, entry.superOptions);
            entry.superOptions = trim_copy(entry.superOptions);
            return true;
        }

        std::vector<MountInfoEntry> parse_mount_info(const std::string &raw) {
            std::vector<MountInfoEntry> entries;
            std::istringstream stream(raw);
            std::string line;
            while (std::getline(stream, line)) {
                MountInfoEntry entry;
                if (parse_mount_info_line(line, entry)) {
                    entries.push_back(entry);
                }
            }
            std::sort(
                    entries.begin(),
                    entries.end(),
                    [](const MountInfoEntry &left, const MountInfoEntry &right) {
                        return left.id < right.id;
                    }
            );
            return entries;
        }

        void add_finding(
                MountSnapshot &snapshot,
                std::unordered_set<std::string> &dedupe,
                const std::string &group,
                const std::string &severity,
                const std::string &label,
                const std::string &value,
                const std::string &detail
        ) {
            const std::string key = group + "|" + label + "|" + value + "|" + detail;
            if (!dedupe.insert(key).second) {
                return;
            }
            snapshot.findings.push_back(
                    MountFindingRecord{
                            group,
                            severity,
                            sanitize_field(label),
                            sanitize_field(value),
                            sanitize_field(detail),
                    }
            );
        }

        bool is_system_partition(const std::string &path) {
            static const std::array<const char *, 6> kPaths = {
                    "/system",
                    "/system_root",
                    "/vendor",
                    "/product",
                    "/system_ext",
                    "/odm",
            };
            return std::find(kPaths.begin(), kPaths.end(), path) != kPaths.end();
        }

        bool starts_with(const std::string &value, const std::string &prefix) {
            return value.rfind(prefix, 0) == 0;
        }

        std::string join_optional_fields(const std::vector<std::string> &fields) {
            std::string joined;
            for (size_t index = 0; index < fields.size(); ++index) {
                joined += fields[index];
                if (index + 1 < fields.size()) {
                    joined += " ";
                }
            }
            return joined;
        }

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
                    add_finding(
                            snapshot,
                            dedupe,
                            "ARTIFACTS",
                            "WARNING",
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
                                                                     "DANGER"},
                                                                    {"/debug_ramdisk/userdebug_plat_sepolicy.cil",
                                                                     "userdebug sepolicy", false,
                                                                     "DANGER"},
                                                                    {"/debug_ramdisk/force_debuggable",
                                                                     "force_debuggable", false,
                                                                     "DANGER"},
                                                                    {"/debug_ramdisk/force_adb",
                                                                     "force_adb", false, "DANGER"},
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
                    if (spec.metaHybrid) {
                        snapshot.metaHybridMountDetected = true;
                    } else {
                        snapshot.hybridMountDetected = true;
                    }
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

                if (lowerSource.find(".magisk") != std::string::npos ||
                    lowerTarget.find(".magisk") != std::string::npos ||
                    lowerTarget.find("/data/adb/modules") != std::string::npos ||
                    lowerSource.find("magisk/mirror") != std::string::npos) {
                    snapshot.magiskMountDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "ARTIFACTS",
                            "DANGER",
                            "Magisk mounts",
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
                                "DANGER",
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
                                "DANGER",
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
                                "DANGER",
                                "Loop device mount",
                                entry.target,
                                entry.source + " -> " + entry.target
                        );
                    }

                    if (lowerSource.find("/dev/mapper/") == std::string::npos &&
                        lowerSource.find("/dev/block/dm-") == std::string::npos &&
                        lowerFs != "overlay" &&
                        lowerFs != "overlayfs") {
                        snapshot.dmVerityBypassDetected = true;
                        add_finding(
                                snapshot,
                                dedupe,
                                "RUNTIME",
                                "WARNING",
                                "Direct block mount",
                                entry.target,
                                "Expected dm-verity mapper source, got " + entry.source
                        );
                    }
                }

                if (lowerFs == "tmpfs" &&
                    (lowerTarget == "/sbin" || lowerTarget == "/.magisk" ||
                     lowerTarget == "/patch_hw" || lowerTarget == "/dev/meta_hybird_mnt")) {
                    snapshot.suspiciousTmpfsDetected = true;
                    snapshot.tmpfsSizeAnomaly = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "FILESYSTEM",
                            "WARNING",
                            "Suspicious tmpfs",
                            entry.target,
                            entry.source + " -> " + entry.target + " (" + entry.options + ")"
                    );
                }

                if (lowerSource.find("ksu") != std::string::npos ||
                    lowerSource.find("kernelsu") != std::string::npos ||
                    lowerSource.find("magic_mount") != std::string::npos ||
                    lowerOptions.find("workdir=/data/adb") != std::string::npos) {
                    snapshot.ksuOverlayDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "ARTIFACTS",
                            "DANGER",
                            "KernelSU or magic-mount overlay",
                            entry.target,
                            entry.source + " -> " + entry.target
                    );
                }

                if (lowerSource.find("meta-hybrid") != std::string::npos ||
                    lowerSource.find("meta_hybird") != std::string::npos ||
                    lowerSource.find("magic_mount") != std::string::npos ||
                    lowerTarget.find(".magic_mount") != std::string::npos) {
                    snapshot.metaHybridMountDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "ARTIFACTS",
                            "DANGER",
                            "Meta-Hybrid or magic mount",
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

            int dataDataMountId = -1;

            for (size_t index = 0; index < entries.size(); ++index) {
                const MountInfoEntry &entry = entries[index];
                const std::string optionalJoined = join_optional_fields(entry.optionalFields);
                const std::string lowerOptional = lowercase_copy(optionalJoined);
                const std::string lowerSuper = lowercase_copy(entry.superOptions);

                if (entry.target == "/data/data") {
                    dataDataMountId = entry.id;
                }

                if (is_system_partition(entry.target) && entry.root != "/") {
                    snapshot.bindMountDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "DANGER",
                            "Bind mount root",
                            entry.target,
                            "root=" + entry.root + ", source=" + entry.source
                    );
                }

                if (is_system_partition(entry.target) &&
                    (lowerSuper.find("context=") != std::string::npos ||
                     lowerSuper.find("fscontext=") != std::string::npos ||
                     lowerSuper.find("defcontext=") != std::string::npos ||
                     lowerSuper.find("rootcontext=") != std::string::npos)) {
                    snapshot.mountOptionsAnomaly = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "DANGER",
                            "SELinux mount override",
                            entry.target,
                            entry.superOptions
                    );
                }

                if (entry.target == "/" && lowerOptional.find("shared:") == std::string::npos &&
                    lowerOptional.find("master:") == std::string::npos &&
                    lowerOptional.find("unbindable") == std::string::npos) {
                    snapshot.mountPropagationAnomaly = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "WARNING",
                            "Root mount propagation",
                            "Private",
                            optionalJoined.empty()
                            ? "No shared/master propagation markers were present on the root mount."
                            : optionalJoined
                    );
                }

                if (entry.target == "/apex/com.android.art" && index + 1 < entries.size() &&
                    entries[index + 1].id > entry.id + 1) {
                    snapshot.mountIdLoopholeDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "DANGER",
                            "Mount ID loophole",
                            "Gap after ART",
                            "Expected next ID " + std::to_string(entry.id + 1) + ", got " +
                            std::to_string(entries[index + 1].id)
                    );
                }

                if (entry.target == "/data_mirror" && index > 0) {
                    const MountInfoEntry &previous = entries[index - 1];
                    if (previous.id + 1 != entry.id &&
                        previous.target.find("/data/user") == std::string::npos) {
                        snapshot.mountIdLoopholeDetected = true;
                        add_finding(
                                snapshot,
                                dedupe,
                                "CONSISTENCY",
                                "DANGER",
                                "Mount ID loophole",
                                "Gap before /data_mirror",
                                "Previous mount " + previous.target + " has ID " +
                                std::to_string(previous.id)
                        );
                    }
                }
            }

#ifdef __NR_statx
            snapshot.statxSupported = is_statx_supported();

            if (snapshot.statxSupported && dataDataMountId > 0) {
                struct statx stx{};
                const int statxResult = static_cast<int>(
                        syscall(__NR_statx, AT_FDCWD, "/data/data", AT_NO_AUTOMOUNT,
                                STATX_BASIC_STATS | kStatxMountIdMask, &stx)
                );
                if (statxResult == 0 && (stx.stx_mask & kStatxMountIdMask) != 0 &&
                    stx.stx_mnt_id != static_cast<std::uint64_t>(dataDataMountId)) {
                    snapshot.statxMntIdMismatch = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "DANGER",
                            "statx mount ID mismatch",
                            "/data/data",
                            "mountinfo=" + std::to_string(dataDataMountId) + ", statx=" +
                            std::to_string(static_cast<unsigned long long>(stx.stx_mnt_id))
                    );
                }
            }

            struct StatxCheck {
                const char *path;
                const char *label;
            };
            static const std::array<StatxCheck, 3> kChecks = {{
                                                                      {"/system/bin", "System bin"},
                                                                      {"/system/lib64",
                                                                       "System lib64"},
                                                                      {"/vendor/bin", "Vendor bin"},
                                                              }};

            std::map<std::string, int> mountIds;
            for (const MountInfoEntry &entry: entries) {
                mountIds[entry.target] = entry.id;
            }

            if (snapshot.statxSupported) {
                for (const StatxCheck &check: kChecks) {
                    struct statx stx{};
                    const int statxResult = static_cast<int>(
                            syscall(__NR_statx, AT_FDCWD, check.path, AT_NO_AUTOMOUNT,
                                    STATX_BASIC_STATS | kStatxMountIdMask, &stx)
                    );
                    if (statxResult != 0 || (stx.stx_mask & kStatxMountIdMask) == 0) {
                        continue;
                    }

                    const bool mountRootFlagKnown =
                            (stx.stx_attributes_mask & kStatxMountRootMask) != 0;
                    const bool isMountRoot =
                            mountRootFlagKnown && (stx.stx_attributes & kStatxMountRootMask) != 0;
                    if (isMountRoot) {
                        snapshot.statxMountRootAnomaly = true;
                        add_finding(
                                snapshot,
                                dedupe,
                                "CONSISTENCY",
                                "WARNING",
                                "statx mount root",
                                check.path,
                                std::string(check.label) +
                                " unexpectedly reports mount-root attributes."
                        );
                    }

                    const auto mountIdIt = mountIds.find(check.path);
                    if (mountIdIt != mountIds.end() &&
                        static_cast<unsigned long long>(stx.stx_mnt_id) !=
                        static_cast<unsigned long long>(mountIdIt->second)) {
                        snapshot.statxMountRootAnomaly = true;
                        add_finding(
                                snapshot,
                                dedupe,
                                "CONSISTENCY",
                                "DANGER",
                                "statx mount cross-check",
                                check.path,
                                "mountinfo=" + std::to_string(mountIdIt->second) + ", statx=" +
                                std::to_string(static_cast<unsigned long long>(stx.stx_mnt_id))
                        );
                    }
                }
            }
#else
            snapshot.statxSupported = false;
#endif
        }

        void detect_namespace(
                MountSnapshot &snapshot,
                std::unordered_set<std::string> &dedupe
        ) {
            bool selfReadable = false;
            const std::string selfNs = read_namespace_link("/proc/self/ns/mnt", &selfReadable);
            if (!selfReadable) {
                return;
            }

            bool initReadable = false;
            const std::string initNs = read_namespace_link("/proc/1/ns/mnt", &initReadable);
            snapshot.initNamespaceReadable = initReadable;
            if (!initReadable) {
                return;
            }

            snapshot.namespaceAnomalyDetected = true;
            if (selfNs != initNs) {
                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "INFO",
                        "Namespace split",
                        "Different from init",
                        "self=" + selfNs + ", init=" + initNs
                );
            } else {
                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "WARNING",
                        "Namespace split",
                        "Matches init",
                        "The app shares the same mount namespace as init, which is unusual for an unprivileged app."
                );
            }
        }

        void detect_filesystems(
                MountSnapshot &snapshot,
                const std::vector<MountEntry> &mounts,
                std::unordered_set<std::string> &dedupe
        ) {
            bool filesystemsReadable = false;
            const std::string filesystems = read_file_direct("/proc/filesystems", 16384,
                                                             &filesystemsReadable);
            snapshot.filesystemsReadable = filesystemsReadable;
            if (filesystemsReadable && contains_ignore_case(filesystems, "overlay")) {
                snapshot.overlayfsKernelSupport = true;
            }

            struct StatFsCheck {
                const char *path;
                const char *label;
            };
            static const std::array<StatFsCheck, 6> kChecks = {{
                                                                       {"/system", "System"},
                                                                       {"/vendor", "Vendor"},
                                                                       {"/product", "Product"},
                                                                       {"/system_ext",
                                                                        "System extension"},
                                                                       {"/odm", "ODM"},
                                                                       {"/data", "Data"},
                                                               }};

            for (const StatFsCheck &check: kChecks) {
                struct statfs st{};
                if (statfs(check.path, &st) != 0) {
                    continue;
                }

                const std::string path(check.path);
                if ((path == "/system" || path == "/vendor" ||
                     path == "/product" || path == "/system_ext" ||
                     path == "/odm") &&
                    static_cast<unsigned long>(st.f_type) ==
                    static_cast<unsigned long>(OVERLAYFS_SUPER_MAGIC)) {
                    snapshot.systemFsTypeAnomaly = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "FILESYSTEM",
                            "DANGER",
                            "System filesystem type",
                            check.path,
                            std::string(check.label) + " resolved to overlayfs."
                    );
                }

                if (static_cast<unsigned long>(st.f_type) ==
                    static_cast<unsigned long>(TMPFS_MAGIC) &&
                    (path == "/system" || path == "/vendor")) {
                    snapshot.tmpfsSizeAnomaly = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "FILESYSTEM",
                            "WARNING",
                            "System tmpfs",
                            check.path,
                            std::string(check.label) +
                            " resolved to tmpfs, which is unusual for stock partitions."
                    );
                }
            }

            for (const MountEntry &entry: mounts) {
                if (lowercase_copy(entry.fsType) == "tmpfs" && entry.target == "/sbin") {
                    snapshot.tmpfsSizeAnomaly = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "FILESYSTEM",
                            "WARNING",
                            "Tmpfs mount",
                            entry.target,
                            entry.options
                    );
                }
            }
        }

        void detect_inconsistent_mount(
                MountSnapshot &snapshot,
                const std::vector<MountEntry> &mounts,
                std::unordered_set<std::string> &dedupe
        ) {
            std::array<char, PATH_MAX> resolved{};
            const ssize_t resolvedLength = syscall_readlink_path("/proc/self/exe", resolved.data(),
                                                                 resolved.size() - 1);
            if (resolvedLength <= 0) {
                return;
            }
            resolved[static_cast<size_t>(resolvedLength)] = '\0';

            struct statfs directFs{};
            struct statfs resolvedFs{};
            if (statfs("/proc/self/exe", &directFs) != 0 ||
                statfs(resolved.data(), &resolvedFs) != 0) {
                return;
            }

            if (directFs.f_type != resolvedFs.f_type) {
                snapshot.inconsistentMountDetected = true;
                add_finding(
                        snapshot,
                        dedupe,
                        "CONSISTENCY",
                        "DANGER",
                        "Mount consistency",
                        "Filesystem mismatch",
                        "direct=0x" + std::to_string(static_cast<unsigned long>(directFs.f_type)) +
                        ", resolved=0x" +
                        std::to_string(static_cast<unsigned long>(resolvedFs.f_type))
                );
                return;
            }

            if (static_cast<unsigned long>(directFs.f_type) ==
                static_cast<unsigned long>(OVERLAYFS_SUPER_MAGIC)) {
                const bool hasSystemOverlay = std::any_of(
                        mounts.begin(),
                        mounts.end(),
                        [](const MountEntry &entry) {
                            return (entry.target == "/system" || entry.target == "/system/bin") &&
                                   (entry.fsType == "overlay" || entry.fsType == "overlayfs");
                        }
                );
                if (!hasSystemOverlay) {
                    snapshot.inconsistentMountDetected = true;
                    add_finding(
                            snapshot,
                            dedupe,
                            "CONSISTENCY",
                            "DANGER",
                            "Mount consistency",
                            "Hidden overlayfs",
                            "statfs reported overlayfs for /proc/self/exe, but mount tables did not show a matching system overlay."
                    );
                }
            }
        }

    }  // namespace

    MountSnapshot collect_snapshot() {
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
        const std::vector<MountInfoEntry> mountInfo = parse_mount_info(mountInfoRaw);

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
        out << "PEER_GROUP_LOOPHOLE=" << flag(snapshot.peerGroupLoopholeDetected) << '\n';
        out << "MINOR_DEV_LOOPHOLE=" << flag(snapshot.minorDevLoopholeDetected) << '\n';
        out << "FUTILE_HIDE=" << flag(snapshot.futileHideDetected) << '\n';
        out << "STATX_MNT_ID_MISMATCH=" << flag(snapshot.statxMntIdMismatch) << '\n';
        out << "BIND_MOUNT_DETECTED=" << flag(snapshot.bindMountDetected) << '\n';
        out << "MOUNT_OPTIONS_ANOMALY=" << flag(snapshot.mountOptionsAnomaly) << '\n';
        out << "STATX_MOUNT_ROOT_ANOMALY=" << flag(snapshot.statxMountRootAnomaly) << '\n';
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
