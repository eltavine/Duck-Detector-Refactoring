// SPDX-License-Identifier: Apache-2.0
#include "zygisk/heuristic_evidence.h"
#include "zygisk/probes/fd_probe.h"
#include "zygisk/probes/vmap_probe.h"

#include <cassert>

using namespace duckdetector::zygisk;

MapEntry executable(const std::string &path, const unsigned long inode = 1) {
    MapEntry map;
    map.path = path;
    map.perms = "r-xp";
    map.inode = inode;
    return map;
}

int main() {
    const std::string root = "/data/app/~~ZRBshrwXZYZRT9P94L6Zfw==/"
                             "com.google.android.webview-EhjSUe61CRiru01kMjxgJw==";
    const auto clean_maps = analyze_executable_maps({
            executable(root + "/base.apk"), executable(root + "/oat/arm64/base.odex"),
    });
    const auto clean_fds = analyze_fd_targets(std::vector<std::string>(14, root + "/base.apk"));
    assert(clean_maps.traces.empty() && clean_maps.heuristic_families.empty());
    assert(clean_fds.traces.empty() && clean_fds.heuristic_families.empty());
    assert(count_heuristic_families({&clean_maps, &clean_fds}) == 0);
    assert(!analyze_executable_maps({}).available);
    assert(analyze_fd_targets({}).available);

    for (const std::string &path: std::initializer_list<std::string>{
            "/data/adb/modules/zygisk/lib.so", root + "/lib/arm64/libriru.so",
            root + "/base.apk!/lib/arm64-v8a/libzygisk.so",
            "/data/app/org.riru.example-EhjSUe61CRiru01kMjxgJw==/base.apk",
            "/data/app/org.example-1/lib/arm64/libpayload.so (deleted)",
    }) {
        const auto maps = analyze_executable_maps({executable(path)});
        const auto fds = analyze_fd_targets({path, path});
        assert(!maps.traces.empty() && !fds.traces.empty());
        assert(maps.traces.front().detail.find(path) != std::string::npos);
        assert(count_heuristic_families({&maps, &fds}) == 1);
        // Independent runtime mechanisms can still corroborate a path finding.
        ProbeResult atexit;
        atexit.heuristic_families.insert(HeuristicFamily::kAtexit);
        assert(count_heuristic_families({&maps, &fds, &atexit}) == 2);
    }
    const auto maps_and_jit = analyze_executable_maps({
            executable("/data/adb/modules/zygisk/lib.so"),
            executable("/memfd:jit-cache", 2), executable("/memfd:jit-cache", 3),
    });
    const auto fds = analyze_fd_targets({"/data/adb/modules/zygisk/lib.so"});
    assert(count_heuristic_families({&maps_and_jit}) == 1);
    assert(count_heuristic_families({&maps_and_jit, &fds}) == 2);
    MapEntry non_exec = executable("/data/adb/modules/zygisk/lib.so");
    non_exec.perms = "r--p";
    assert(analyze_executable_maps({non_exec}).traces.empty());
    assert(analyze_fd_targets({"/data/user/0/org.example/cache/zygisk.tmp"}).traces.empty());
}
