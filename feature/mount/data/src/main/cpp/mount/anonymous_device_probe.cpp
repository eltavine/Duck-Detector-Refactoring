// SPDX-License-Identifier: Apache-2.0
#include "mount/anonymous_device_probe.h"
#include "mount/detector_internal.h"
#include <iterator>
#include <sys/statfs.h>
#include <sys/sysmacros.h>

namespace duckdetector::mount::detail {
    namespace {
        constexpr long kCgroupMagic = 0x27e0eb;
        constexpr long kCgroup2Magic = 0x63677270;
        constexpr long kFuseMagic = 0x65735546;
        constexpr size_t kMaxReportedGaps = 8;

        struct Anchor {
            unsigned int minor = 0;
            std::string path;
        };

        bool read_anchor(const std::string &path, uint64_t expectedType, Anchor &anchor,
                         std::string &failures, bool &wrongType) {
            struct stat st{};
            if (syscall_stat_path(path.c_str(), &st) != 0) {
                failures += path + ": stat errno=" + std::to_string(errno) + "; ";
                return false;
            }
            struct statfs fs{};
            if (statfs(path.c_str(), &fs) != 0) {
                failures += path + ": statfs errno=" + std::to_string(errno) + "; ";
                return false;
            }
            if (major(st.st_dev) != 0 || minor(st.st_dev) == 0 || static_cast<uint64_t>(fs.f_type) != expectedType) {
                wrongType = true;
                failures += path + ": unexpected device/filesystem; ";
                return false;
            }
            anchor = {static_cast<unsigned int>(minor(st.st_dev)), path};
            return true;
        }

        bool app_private_tmpfs(const MountInfoEntry &entry) {
            if (entry.major != 0 || entry.fsType != "tmpfs") return false;
            // Android 14 Zygote isolateAppData/isolateJitProfile creates these mounts.
            // Other processes' copies are invisible here; stop before the first visible one.
            for (const auto *prefix: {"/data/data", "/data/user", "/data/user_de",
                                      "/data/misc/profiles"}) {
                const std::string path(prefix);
                if (entry.target == path || starts_with(entry.target, path + "/")) return true;
            }
            return false;
        }
    }

    AnonymousDeviceObservation observe_anonymous_devices(
            const std::vector<MountInfoEntry> &entries,
            bool completeCapture,
            const std::string &externalStorageRoot
    ) {
        if (!completeCapture || entries.empty()) {
            return {AnonymousDeviceState::Unavailable,
                    "A complete, valid /proc/self/mountinfo capture is required."};
        }
        Anchor floor;
        std::string failures;
        bool wrongType = false;
        for (const auto &[path, type]: std::array<std::pair<const char *, uint64_t>, 3>{{
                {"/tmp", TMPFS_MAGIC}, {"/dev/cpuset", kCgroupMagic},
                {"/sys/fs/cgroup", kCgroup2Magic}}}) {
            Anchor candidate;
            if (read_anchor(path, type, candidate, failures, wrongType) && candidate.minor > floor.minor) {
                floor = candidate;
            }
        }
        if (floor.path.empty()) {
            return {wrongType ? AnonymousDeviceState::Unsupported : AnonymousDeviceState::Unavailable,
                    "No usable tmpfs/cgroup floor. " + failures};
        }
        if (externalStorageRoot.empty() || externalStorageRoot.front() != '/') {
            return {AnonymousDeviceState::Unavailable,
                    "The current user's external-storage path is unavailable."};
        }
        // Environment supplies this user's path. Marker files are optional; neither create
        // them nor request storage permission just to establish the FUSE boundary.
        Anchor ceiling;
        failures.clear();
        wrongType = false;
        for (const auto &suffix: {"/Android/data/.nomedia", "/Android/obb/.nomedia", ""}) {
            if (read_anchor(externalStorageRoot + suffix, kFuseMagic, ceiling, failures, wrongType)) break;
        }
        if (ceiling.path.empty()) {
            return {wrongType ? AnonymousDeviceState::Unsupported : AnonymousDeviceState::Unavailable,
                    "No accessible FUSE ceiling for this user. " + failures};
        }
        if (ceiling.minor <= floor.minor) {
            return {AnonymousDeviceState::Inconclusive,
                    "Anchor order is not usable: " + floor.path + "=0:" + std::to_string(floor.minor) +
                    ", " + ceiling.path + "=0:" + std::to_string(ceiling.minor) + "."};
        }
        const Anchor fuseCeiling = ceiling;
        bool appBoundary = false;
        size_t overlays = 0;
        for (const auto &entry: entries) {
            if (entry.fsType == "overlay" || entry.fsType == "overlayfs") ++overlays;
            if (app_private_tmpfs(entry) && entry.minor > floor.minor && entry.minor < ceiling.minor) {
                ceiling = {entry.minor, entry.target};
                appBoundary = true;
            }
        }

        std::map<unsigned int, std::string> visible;
        for (const auto &entry: entries) {
            if (entry.major == 0 && entry.minor > floor.minor && entry.minor < ceiling.minor) {
                visible.emplace(entry.minor, entry.target);
            }
        }
        std::string detail = "Window: " + floor.path + "=0:" + std::to_string(floor.minor) +
                " .. " + ceiling.path + "=0:" + std::to_string(ceiling.minor) +
                "; visible unique devices=" + std::to_string(visible.size()) + ". Only interior intervals between visible devices are compared. ";
        if (appBoundary) {
            detail += "Window stops before app-private tmpfs churn; coverage is partial. FUSE ceiling: " +
                    fuseCeiling.path + "=0:" + std::to_string(fuseCeiling.minor) + ". ";
        }
        if (visible.size() < 2) {
            return {AnonymousDeviceState::Inconclusive, detail + "Too few interior devices to compare."};
        }

        size_t gaps = 0;
        for (auto previous = visible.begin(), current = std::next(previous);
             current != visible.end(); previous = current++) {
            // Work per adjacent device, never per missing integer: large IDs cannot
            // turn a namespace observation into an unbounded scan or output.
            if (static_cast<uint64_t>(current->first) - previous->first <= 1) continue;
            if (gaps < kMaxReportedGaps) {
                detail += "Gap 0:" + std::to_string(previous->first + 1) + "..0:" +
                        std::to_string(current->first - 1) + " between " + previous->second +
                        " and " + current->second + ". ";
            }
            ++gaps;
        }
        detail += "Gap runs=" + std::to_string(gaps) + ". ";
        if (gaps > kMaxReportedGaps) detail += "Only the first eight ranges are shown. ";
        // ACK 5.15/6.1/6.6 fs/overlayfs/super.c allocates pseudo_dev values which
        // need not appear in any mountinfo. Do not infer credits from lowerdir text
        // or assume allocation order makes those values adjacent to an overlay ID.
        if (overlays > 0) {
            detail += "Overlayfs records=" + std::to_string(overlays) +
                    "; layer pseudo-devices cannot be fully accounted for from this view. ";
        }
        // ACK fs/super.c free_anon_bdev releases IDs: lowest-free allocation does
        // not imply a dense live set. A gap never proves an allocated/hidden mount.
        detail += "Released IDs, kernel-only allocations and other namespaces can explain gaps. "
                  "These are non-atomic observations, not proof of root or Vector; bind mounts "
                  "reuse a superblock and may leave no additional anonymous device number.";
        return {overlays > 0 ? AnonymousDeviceState::Inconclusive :
                appBoundary ? AnonymousDeviceState::Partial :
                gaps > 0 ? AnonymousDeviceState::Observed : AnonymousDeviceState::NoGaps, detail};
    }

    const char *anonymous_device_state_key(AnonymousDeviceState state) {
        switch (state) {
            case AnonymousDeviceState::Unavailable: return "UNAVAILABLE";
            case AnonymousDeviceState::Unsupported: return "UNSUPPORTED";
            case AnonymousDeviceState::Inconclusive: return "INCONCLUSIVE";
            case AnonymousDeviceState::Partial: return "PARTIAL";
            case AnonymousDeviceState::Observed: return "OBSERVED";
            case AnonymousDeviceState::NoGaps: return "NO_GAPS";
        }
        return "UNAVAILABLE";
    }
}
