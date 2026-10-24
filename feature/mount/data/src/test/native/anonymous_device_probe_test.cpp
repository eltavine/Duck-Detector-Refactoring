// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <map>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include "mount/detector_internal.h"

struct PathState {
    unsigned int minor;
    long type;
    unsigned int major = 0;
    int statError = 0;
    int statfsError = 0;
};
static std::map<std::string, PathState> paths;
static std::vector<std::string> queried;
int statfs(const char *path, struct statfs *out) {
    const auto &value = paths.at(path);
    if (value.statfsError) { errno = value.statfsError; return -1; }
    out->f_type = value.type;
    return 0;
}
namespace duckdetector::mount::detail {
    int syscall_stat_path(const char *path, struct stat *out) {
        queried.emplace_back(path);
        const auto found = paths.find(path);
        if (found == paths.end()) { errno = ENOENT; return -1; }
        if (found->second.statError) { errno = found->second.statError; return -1; }
        out->st_dev = makedev(found->second.major, found->second.minor);
        return 0;
    }
    bool starts_with(const std::string &value, const std::string &prefix) {
        return value.rfind(prefix, 0) == 0;
    }
}
#define TMPFS_MAGIC 0x01021994
#include "mount/anonymous_device_probe.cpp"

using namespace duckdetector::mount::detail;
static MountInfoEntry entry(unsigned int minor, std::string target = "/boot", std::string fs = "tmpfs") {
    MountInfoEntry result;
    result.minor = minor;
    result.target = std::move(target);
    result.fsType = std::move(fs);
    return result;
}
static void reset() {
    paths = {{"/tmp", {30, TMPFS_MAGIC}}, {"/storage/emulated/10", {100, 0x65735546}}};
    queried.clear();
}
static AnonymousDeviceObservation observe(std::vector<MountInfoEntry> entries) {
    return observe_anonymous_devices(entries, true, "/storage/emulated/10");
}
int main() {
    reset();
    const auto gap = observe({entry(31, "/a"), entry(33, "/b")});
    assert(gap.state == AnonymousDeviceState::Observed);
    assert(gap.detail.find("Gap 0:32..0:32 between /a and /b") != std::string::npos);
    assert(gap.detail.find("not proof of root or Vector") != std::string::npos);
    assert(gap.detail.find("/storage/emulated/10=0:100") != std::string::npos);
    assert(std::none_of(queried.begin(), queried.end(), [](const auto &p) {
        return p.find("/storage/emulated/0") != std::string::npos;
    })); // Missing optional .nomedia files must fall back to this user's root.

    // Bind mounts duplicate the same superblock device: order and duplicates do not add gaps.
    const auto binds = observe({entry(33), entry(31), entry(32), entry(31, "/bind")});
    assert(binds.state == AnonymousDeviceState::NoGaps);
    assert(binds.detail.find("visible unique devices=3") != std::string::npos);
    // The same 32 gap can follow a legitimate free_anon_bdev(32). It stays an
    // observation, never a claim that 32 is allocated or that root was detected.
    assert(anonymous_device_state_key(gap.state) == std::string("OBSERVED"));

    auto block = entry(32); block.major = 253;
    assert(observe({entry(31), block, entry(33)}).state == AnonymousDeviceState::Observed);
    assert(observe({entry(31), entry(33, "/product", "overlay")}).state == AnonymousDeviceState::Inconclusive);
    assert(observe({entry(31), entry(32, "/product", "overlayfs")}).state == AnonymousDeviceState::Inconclusive);
    const auto app = observe({entry(31), entry(32), entry(33, "/data/user/10"), entry(80)});
    assert(anonymous_device_state_key(app.state) == std::string("PARTIAL"));
    assert(app.detail.find("Window stops before app-private") != std::string::npos);
    assert(app.detail.find("FUSE ceiling: /storage/emulated/10=0:100") != std::string::npos);
    const auto partialGap = observe({entry(31), entry(33), entry(34, "/data/user/10"), entry(80)});
    assert(anonymous_device_state_key(partialGap.state) == std::string("PARTIAL"));
    assert(partialGap.detail.find("Gap 0:32..0:32") != std::string::npos);
    assert(observe({entry(31, "/data/misc/profiles/cur"), entry(80)}).state == AnonymousDeviceState::Inconclusive);
    assert(observe({entry(31), entry(33, "/data/user_backup")}).state == AnonymousDeviceState::Observed);
    assert(observe({entry(31)}).state == AnonymousDeviceState::Inconclusive);

    queried.clear();
    assert(observe_anonymous_devices({entry(31), entry(33)}, false, "/storage/emulated/10").state == AnonymousDeviceState::Unavailable);
    assert(queried.empty());
    assert(observe_anonymous_devices({}, true, "/storage/emulated/10").state == AnonymousDeviceState::Unavailable);
    assert(observe_anonymous_devices({entry(31), entry(33)}, true, "").state == AnonymousDeviceState::Unavailable);

    reset(); paths["/tmp"].statError = EACCES;
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Unavailable);
    reset(); paths["/tmp"].statfsError = EIO;
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Unavailable);
    reset(); paths["/tmp"].major = 253;
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Unsupported);
    reset(); paths["/tmp"].type = 0xef53;
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Unsupported);
    reset(); paths.erase("/tmp"); paths["/dev/cpuset"] = {30, 0x27e0eb};
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Observed);
    reset(); paths.erase("/tmp"); paths["/sys/fs/cgroup"] = {30, 0x63677270};
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Observed);

    reset(); paths.erase("/storage/emulated/10");
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Unavailable);
    reset(); paths["/storage/emulated/10"].type = 0x5dca2df5; // sdcardfs has no FUSE boundary.
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Unsupported);
    reset(); paths["/storage/emulated/10"].minor = 20; // Reused minor, not chronology.
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Inconclusive);
    reset(); paths["/storage/emulated/10/Android/data/.nomedia"] = {100, 0x65735546};
    paths["/storage/emulated/10"].statError = EACCES;
    assert(observe({entry(31), entry(33)}).state == AnonymousDeviceState::Observed);

    reset(); paths["/storage/emulated/10"].minor = (1U << 20) - 1;
    assert(observe({entry(31), entry((1U << 20) - 2)}).state == AnonymousDeviceState::Observed);
    std::vector<MountInfoEntry> many;
    for (unsigned int n = 31; n < 60; n += 2) many.push_back(entry(n));
    const auto capped = observe(many);
    assert(capped.detail.find("Gap runs=14") != std::string::npos);
    assert(capped.detail.find("Only the first eight") != std::string::npos);
}
