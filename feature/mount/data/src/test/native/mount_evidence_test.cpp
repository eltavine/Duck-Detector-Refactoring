// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "mount/detector_internal.h"
#include "common/mount_artifact_markers.h"

long testFsType = 0x794c7630;
static std::string fileData;
static size_t fileOffset;
static size_t readChunk = 7;
static int readError;
static uint64_t resolvedId = 20;
static bool mountIdField = true;
static bool mountRoot = false;
static int statxError = 0;

static long fake_syscall(long number, ...) {
    va_list args;
    va_start(args, number);
    long result = 0;
    if (number == __NR_openat) {
        result = 42;
    } else if (number == __NR_read) {
        (void) va_arg(args, int);
        auto *buffer = va_arg(args, void *);
        const auto capacity = va_arg(args, size_t);
        if (readError) { errno = readError; readError = 0; result = -1; }
        else {
            const auto count = std::min({readChunk, capacity, fileData.size() - fileOffset});
            std::memcpy(buffer, fileData.data() + fileOffset, count);
            fileOffset += count;
            result = static_cast<long>(count);
        }
    } else if (number == __NR_readlinkat) {
        (void) va_arg(args, int);
        const auto *path = va_arg(args, const char *);
        auto *buffer = va_arg(args, char *);
        const auto capacity = va_arg(args, size_t);
        const std::string target = std::string(path) == "/proc/self/exe" ?
                "/system/bin/app_process64" : "mnt:[1]";
        const auto count = std::min(capacity, target.size());
        std::memcpy(buffer, target.data(), count);
        result = static_cast<long>(count);
    } else if (number == __NR_statx) {
        (void) va_arg(args, int);
        (void) va_arg(args, const char *);
        (void) va_arg(args, int);
        (void) va_arg(args, unsigned int);
        auto *stx = va_arg(args, struct statx *);
        if (statxError) { errno = statxError; result = -1; }
        else {
            stx->stx_mask = mountIdField ? 0x1000 : 0;
            stx->stx_mnt_id = resolvedId;
            stx->stx_attributes_mask = 0x2000;
            stx->stx_attributes = mountRoot ? 0x2000 : 0;
        }
    }
    va_end(args);
    return result;
}
#define syscall fake_syscall
#include "mount/detector_support.cpp"
#include "mount/detect_mount_tables.cpp"
#include "mount/detect_filesystems.cpp"
#undef syscall
#include "preload/mountinfo_detectors.cpp"

using namespace duckdetector::mount;
using namespace duckdetector::mount::detail;

static void noDanger(const MountSnapshot &snapshot) {
    for (const auto &finding: snapshot.findings) assert(finding.severity != "DANGER");
}
static MountSnapshot table(const std::vector<MountEntry> &entries) {
    MountSnapshot snapshot;
    std::unordered_set<std::string> dedupe;
    detect_mounts(snapshot, entries, dedupe);
    return snapshot;
}
static MountSnapshot info(const std::vector<MountInfoEntry> &entries) {
    MountSnapshot snapshot;
    std::unordered_set<std::string> dedupe;
    detect_mountinfo(snapshot, entries, dedupe);
    return snapshot;
}

int main() {
    // Full, bounded reads must survive short reads/EINTR and reject partial captures.
    bool readable;
    fileData = "12345678901234567890";
    fileOffset = 0; readError = EINTR;
    assert(read_file_direct("fixture", 20, &readable) == fileData && readable);
    fileOffset = 0;
    assert(read_file_direct("fixture", 19, &readable).empty() && !readable);
    fileOffset = 0; readError = EIO;
    assert(read_file_direct("fixture", 100, &readable).empty() && !readable);

    const auto ordinary = table({{"/dev/block/by-name/vendor", "/vendor", "ext4", "ro"}});
    noDanger(ordinary);
    assert(!ordinary.dmVerityBypassDetected);
    noDanger(table({{"/dev/block/loop0", "/system", "ext4", "rw"}}));
    noDanger(table({{"overlay", "/system", "overlay", "rw"}}));
    noDanger(table({{"/dev/block/ksu_storage", "/data/adb_backup", "ext4", "ro"}}));
    const auto genericRoot = table({{"/dev/block/dm-0", "/data/adb/modules/test", "ext4", "ro"}});
    assert(genericRoot.rootMountArtifactDetected && !genericRoot.magiskMountDetected);
    const auto root = table({{"KSU", "/system", "overlay", "rw"}});
    assert(root.ksuOverlayDetected);
    assert(std::any_of(root.findings.begin(), root.findings.end(), [](const auto &f) { return f.severity == "DANGER"; }));

    const std::string raw =
        "90 1 0:1 / /data/data rw - tmpfs tmpfs rw\n"
        "20 1 0:2 / /data/user/0 rw - ext4 /dev/block/dm-0 rw\n"
        "10 1 0:3 /vendor /vendor ro context=u:object_r:vendor_file:s0 - ext4 /dev/block/by-name/vendor ro\n";
    for (const auto &device: {"0:999999999999999999999999999999", "0:1suffix", "-1:2"}) {
        const std::string invalid = "1 1 " + std::string(device) + " / /system ro - ext4 disk ro";
        assert(parse_mount_info(invalid).empty());
        duckdetector::preload::MountInfoEntry early;
        assert(!duckdetector::preload::parse_mountinfo_line(invalid, early));
    }
    duckdetector::preload::MountInfoEntry propagation;
    assert(duckdetector::preload::parse_mountinfo_line(
            "1 1 0:1 / / rw shared:3 master:1 - tmpfs tmpfs rw", propagation));
    assert(propagation.peerGroups.size() == 2);
    bool complete = false;
    const auto entries = parse_mount_info(raw, &complete);
    assert(complete);
    const auto partial = parse_mount_info(raw + "malformed record\n", &complete);
    assert(!complete && partial.size() == entries.size());
    assert(parse_mount_info("", &complete).empty() && !complete);
    parse_mount_info("1 1 0:1 / / rw - tmpfs tmpfs", &complete);
    assert(!complete);
    assert(entries[0].id == 90 && entries[1].id == 20); // Preserve capture order.
    const auto resolved = info(entries); // statx follows /data/data to a different visible mount.
    assert(!resolved.statxMntIdMismatch);
    noDanger(resolved);
    assert(!resolved.bindMountDetected && !resolved.mountOptionsAnomaly);
    auto moduleRoot = entries;
    moduleRoot.back().root = "/adb/modules/example/system";
    const auto exposed = info(moduleRoot);
    assert(std::any_of(exposed.findings.begin(), exposed.findings.end(), [](const auto &f) { return f.severity == "DANGER"; }));
    auto stacked = entries;
    stacked.push_back(entries[0]);
    stacked.back().id = 91;
    resolvedId = 90;
    assert(!info(stacked).statxMntIdMismatch);
    resolvedId = 999; // Changed namespace between non-atomic captures: observation only.
    const auto changed = info(entries);
    assert(changed.statxMntIdMismatch);
    noDanger(changed);
    mountRoot = true;
    noDanger(info(entries));
    mountIdField = false;
    const auto unsupported = info(entries);
    assert(!unsupported.statxMntIdMismatch && !unsupported.statxMountRootAttribute && !unsupported.statxSupported);
    statxError = EACCES;
    assert(!info(entries).statxMntIdMismatch);

    MountSnapshot fs;
    std::unordered_set<std::string> dedupe;
    detect_inconsistent_mount(fs, {{"overlay", "/", "overlay", "rw"}}, dedupe);
    assert(!fs.inconsistentMountDetected); // An overlay at / covers the executable too.
    detect_namespace(fs, dedupe); // Equal namespace identities are contextual.
    assert(!fs.namespaceAnomalyDetected);
    noDanger(fs);
    detect_filesystems(fs, {}, dedupe);
    noDanger(fs);

    using duckdetector::common::mount_artifact_labels;
    assert(mount_artifact_labels("/adb/modules_backup", "/system/lspci", "disk-ksu-data").empty());
    assert(mount_artifact_labels("/data/user/0/example/cache/magisk", "/vendor/sui", "ext4").empty());
    assert(!mount_artifact_labels("/", "/system", "/data/adb/modules/example").empty());
    assert(!mount_artifact_labels("/adb/modules/example", "/system", "ext4").empty());
    assert(!mount_artifact_labels("/", "/data/adb/modules/example", "ext4").empty());
}
