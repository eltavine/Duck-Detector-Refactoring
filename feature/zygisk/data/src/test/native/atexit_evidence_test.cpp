// SPDX-License-Identifier: Apache-2.0
#include "zygisk/probes/atexit/table.h"

#include <cassert>
#include <unistd.h>

using namespace duckdetector::zygisk;
using namespace duckdetector::zygisk::atexit;

namespace {
    MapEntry map(uintptr_t start, const std::string &path, const std::string &permissions = "r-xp") {
        MapEntry out;
        out.start = start;
        out.end = start + 0x1000;
        out.perms = permissions;
        out.path = path;
        return out;
    }

    const std::vector<MapEntry> maps{
        map(0x1000, "/apex/com.android.art/lib64/libart.so"),
        map(0x3000, "/system/lib64/libadbconnection.so"),
        map(0x5000, "/apex/com.android.art/lib64/libperfetto_hprof.so"),
        map(0x7000, "/memfd:module (deleted)"),
        map(0x9000, "/data/app/~~random/token/base.apk!lib/arm64-v8a/libapp.so"),
        map(0xb000, "[anon:dalvik-jit-code-cache]"),
    };

    Entry art() { return {0x1010, 0, 0x1020}; }
    Entry app() { return {0x9010, 0, 0x9020}; }

    std::vector<Entry> gap(size_t count) {
        std::vector<Entry> entries(16, art());
        entries.insert(entries.end(), count, Entry{});
        entries.push_back({0x3010, 0, 0x3020});
        entries.push_back(app());
        return entries;
    }
}

int main() {
    char path[] = "/tmp/duck-atexit-maps-XXXXXX";
    const int fd = mkstemp(path);
    assert(fd >= 0);
    constexpr char row[] = "1000-2000 r-xp 1000 fe:abcde 4294967297 /apex/libc.so\n";
    assert(write(fd, row, sizeof(row) - 1) == static_cast<ssize_t>(sizeof(row) - 1));
    close(fd);
    const auto parsed = read_proc_maps(path);
    unlink(path);
    assert(parsed.size() == 1 && parsed[0].inode == UINT64_C(4294967297));
    assert(parsed[0].device_major == 0xfe && parsed[0].device_minor == 0xabcde);

    auto clean = gap(0);
    auto result = interpret_table(clean, maps);
    assert(result.bounded && result.anchored_gaps == 0 && result.anonymous_callbacks == 0);

    result = interpret_table(gap(3), maps);
    assert(result.null_entries == 3 && result.anchored_gaps == 1);
    assert(result.traces.size() == 1 && result.traces[0].severity == SignalSeverity::kWarning);
    assert(interpret_table(gap(2), maps).anchored_gaps == 0);

    assert(interpret_table(gap(26), maps).anchored_gaps == 1);
    const auto dense = interpret_table(gap(27), maps);
    assert(dense.bounded && dense.dense_clearing && dense.anchored_gaps == 0 && dense.traces.empty());
    assert(!interpret_table(gap(26), maps).dense_clearing);

    auto short_art = gap(3);
    short_art.erase(short_art.begin());
    assert(interpret_table(short_art, maps).anchored_gaps == 0);

    auto after_app = std::vector<Entry>{app(), art(), {}, {}, {}, art()};
    assert(interpret_table(after_app, maps).anchored_gaps == 0);

    auto no_boundary = gap(3);
    no_boundary.pop_back();
    assert(!interpret_table(no_boundary, maps).bounded);
    assert(interpret_table(no_boundary, maps).anchored_gaps == 0);

    auto missing = gap(3);
    missing[16] = {0xf010, 0, 0xf020};
    result = interpret_table(missing, maps);
    assert(result.anchored_gaps == 0 && result.unresolved_callbacks == 1);

    auto leading = std::vector<Entry>{{}, {}, {}, art(), app()};
    assert(interpret_table(leading, maps).anchored_gaps == 0);

    auto callbacks = std::vector<Entry>{{0x7010, 0, 0x7020}, app()};
    result = interpret_table(callbacks, maps);
    assert(result.anonymous_callbacks == 1 && result.traces[0].severity == SignalSeverity::kWarning);
    callbacks = {app(), {0x7010, 0, 0x7020}};
    assert(interpret_table(callbacks, maps).anonymous_callbacks == 0);
    callbacks = {{0x1010, 0x7010, 0x1020}, app()};
    assert(interpret_table(callbacks, maps).anonymous_callbacks == 0);
    callbacks = {{0xb010, 0, 0xb020}, app()};
    assert(interpret_table(callbacks, maps).anonymous_callbacks == 0);

    auto perfetto_gap = std::vector<Entry>{art(), {}, {}, {}, {0x1010, 0, 0x5020}, {0x1010, 0, 0x5020}, app()};
    assert(interpret_table(perfetto_gap, maps).anchored_gaps == 1);
    assert(interpret_table({}, maps).traces.empty());
    assert(std::string(state_name(TableState::kPermissionDenied)) == "PERMISSION_DENIED");
}
