// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/avc_lookup_probe.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <sched.h>
#include <string>
#include <time.h>
#include <unistd.h>
#include <vector>
using namespace duckdetector::selinux::avc_lookup;

static std::string mode;
static unsigned writes, clocks, cpus, identities, closes;
static uint64_t ticks;
static int parent_pid() { return 42; }
static uid_t parent_uid() { return mode == "uid" ? 1000 : 10001; }
static int parent_cpu() {
    ++cpus;
    if (mode == "migration" && cpus == 1 + kWarmup + 2) return 6;
    // A move between completed pairs is valid when each pair's endpoints match.
    if (mode == "between_pairs" && cpus > 1 + kWarmup)
        return ((cpus - 2 - kWarmup) / 2) % 2 ? 7 : 0;
    // Regression: after 262 complete pairs, the scheduler selects another CPU
    // for the remaining 250 pairs. Both stretches must remain usable.
    if (mode == "late_switch" && cpus >= 2 + kWarmup + 2 * 262)
        return 7;
    return 5;
}
static int parent_clock(clockid_t id, timespec *out) {
    assert(id == CLOCK_MONOTONIC_RAW);
    ++clocks;
    if (mode == "clock") { errno = EIO; return -1; }
    // Clock reads must not overwrite the write's captured errno.
    errno = EOVERFLOW;
    out->tv_sec = 0;
    out->tv_nsec = ++ticks;
    return 0;
}
static ssize_t parent_write(int fd, const void *ptr, size_t size) {
    assert(fd == 42 && size == kPayloadLength);
    const auto *payload = static_cast<const char *>(ptr);
    const bool a = std::memcmp(payload, kPayloadA, size) == 0;
    assert(a || std::memcmp(payload, kPayloadB, size) == 0);
    const unsigned index = writes++;
    if (index < 2) assert(a == (index == 1)); // B, then A preflight.
    else {
        const unsigned pair = (index - 2) / 2;
        assert(a == (((pair + index - 2) & 1u) == 0)); // AB, BA, including warmup.
    }
    int64_t cost = a ? 300 : 200;
    if (mode == "negative") cost = a ? 100 : 200;
    if (mode == "lower_median" && index >= 2 + 2 * kWarmup) {
        const unsigned pair = (index - 2) / 2 - kWarmup;
        cost = a ? (pair % 32 < 16 ? 199 : 300) : 200;
    }
    ticks += cost;
    if (mode == "short" && index == 0) return 1;
    if (mode == "success" && index == 0) return size;
    errno = mode == "denied" ? EACCES : mode == "eintr" && index == 90 ? EINTR : EINVAL;
    return -1;
}
namespace duckdetector::selinux::avc_lookup {
    int current_cpu() { return parent_cpu(); }
    int read_identity(char *out, unsigned) {
        ++identities;
        const char *value = mode == "domain" || (mode == "identity" && identities > 1)
            ? "u:r:isolated_app:s0" : "u:r:app_zygote:s0:c512,c768";
        strcpy(out, value);
        return 0;
    }
    int read_text(const char *path, char *out, size_t, size_t &length) {
        if (strcmp(path, kStats) == 0) return EACCES; // Counters are optional for timing.
        assert(strcmp(path, kEnforce) == 0);
        out[0] = mode == "permissive" ? '0' : '1'; length = 1;
        return 0;
    }
    int open_attr(int &fd) { fd = 42; return 0; }
    void close_attr(int fd) { assert(fd == 42); ++closes; }
}
// Compile the production loop with syscall seams. No sched_setaffinity seam is
// provided: the unpinned parent collector must never change thread affinity.
#define write parent_write
#define clock_gettime parent_clock
#define getpid parent_pid
#define getuid parent_uid
#define sched_setaffinity forbidden_affinity_change
#include "selinuxpolicy/app_zygote_timing.cpp"
#undef write
#undef clock_gettime
#undef getpid
#undef getuid
#undef sched_setaffinity

static ParentTiming run(const char *test) {
    mode = test;
    writes = clocks = cpus = identities = closes = 0;
    ticks = 100;
    return collect_parent_timing();
}
int main() {
    const auto positive = run("positive");
    assert(positive.protocol == 1 && positive.complete && positive.cpu == 5 && positive.pid == 42);
    assert(positive.pairs == 512 && positive.migrations == 0 && positive.a_slower == 512);
    assert(positive.median_delta_ns == 100 && positive.positive_blocks == 16);
    assert(writes == 2 + 2 * (kWarmup + kPairs) && clocks == 2 * writes && closes == 1);
    const auto negative = run("negative");
    assert(negative.complete && negative.median_delta_ns == -100 && negative.negative_blocks == 16);
    const auto lower = run("lower_median");
    assert(lower.complete && lower.median_delta_ns == -1 && lower.negative_blocks == 16);
    assert(lower.a_slower == 256);
    const auto moved = run("migration");
    assert(!moved.complete && moved.error == EAGAIN && moved.migrations == 1 && moved.pairs == 511);
    assert(moved.medians_available && moved.median_delta_ns == 100 && closes == 1);
    const auto between = run("between_pairs");
    assert(between.complete && between.error == 0 && between.migrations == 0);
    assert(between.pairs == 512 && between.median_delta_ns == 100);
    const auto late = run("late_switch");
    assert(late.complete && late.error == 0 && late.migrations == 0);
    assert(late.pairs == 512 && late.median_delta_ns == 100);
    for (const char *test : {"uid", "domain", "permissive"}) {
        assert(!run(test).complete && writes == 0);
    }
    for (const char *test : {"short", "success", "denied"}) {
        const auto failure = run(test);
        assert(!failure.complete && failure.error != 0 && writes == 1 && closes == 1);
    }
    const auto interrupted = run("eintr");
    assert(!interrupted.complete && interrupted.error == EINTR && writes == 91 && closes == 1);
    const auto clock = run("clock");
    assert(!clock.complete && clock.error == EIO && writes == 0 && closes == 1);
    assert(!run("identity").complete);
}
