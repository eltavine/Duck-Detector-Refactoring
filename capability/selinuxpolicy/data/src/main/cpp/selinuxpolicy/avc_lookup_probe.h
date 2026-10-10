// SPDX-License-Identifier: Apache-2.0
#ifndef DUCKDETECTOR_SELINUX_AVC_LOOKUP_PROBE_H
#define DUCKDETECTOR_SELINUX_AVC_LOOKUP_PROBE_H

#include "common/disposable_child.h"
#include <array>
#include <cstddef>
#include <cstdint>

namespace duckdetector::selinux::avc_lookup {
    constexpr char kCarrier[] = "u:r:app_zygote:s0";
    constexpr char kEnforce[] = "/sys/fs/selinux/enforce";
    constexpr char kStats[] = "/sys/fs/selinux/avc/cache_stats";
    constexpr char kPossibleCpus[] = "/sys/devices/system/cpu/possible";
    // selinux_setprocattr checks SETCURRENT, then converts a value that does not start with a
    // newline. A names a type no policy defines and fails conversion with EINVAL; B skips conversion
    // and fails with EINVAL on the empty SID. Equal lengths keep the copied bytes identical.
    constexpr char kPayloadA[] = "u:r:__selinux_hide_probe_invalid__:s0";
    constexpr char kPayloadB[] = "\n:r:__selinux_hide_probe_invalid__:s0";
    constexpr bool same_tail(const char *a, const char *b) {
        return *a == *b && (*a == '\0' || same_tail(a + 1, b + 1));
    }
    static_assert(sizeof(kPayloadA) == sizeof(kPayloadB) && kPayloadB[0] == '\n' &&
                  same_tail(kPayloadA + 1, kPayloadB + 1));
    constexpr unsigned kPayloadLength = sizeof(kPayloadA) - 1;
    constexpr unsigned kWarmup = 32;
    constexpr unsigned kPairs = 128;
    constexpr unsigned kRounds = 4;
    constexpr unsigned kWrites = 4096;
    // Largest CPU number plus one, and most cache_stats rows, the parsers accept.
    constexpr unsigned kCpuLimit = 256;

    enum class State { kUnavailable, kUnsupported, kPermissionLimited, kTimingOnly, kCollected, kInconclusive };
    enum class Step { kCarrier, kEnforce, kOpen, kControls, kTiming, kAffinity, kCpuMap, kStats, kCounting,
                      kIdentity, kFinished };
    enum class Payload { kNone, kA, kB };

    struct WriteOutcome {
        int error = 0;
        int64_t bytes = -1; // -1: the write failed with error; >=0: the count it returned.
    };
    struct Report {
        State state = State::kUnavailable;
        Step step = Step::kCarrier;
        int error = 0;
        // The write that did not fail with EINVAL, and what it returned; its errno is in error.
        Payload unexpected = Payload::kNone;
        int64_t unexpected_bytes = 0;
        bool identity_changed = false;
        int cpu = -1;
        int cpu_row = -1;
        unsigned cpu_rows = 0;
        unsigned possible_cpus = 0;
        unsigned pairs = 0;
        unsigned rounds = 0;
        std::array<uint32_t, kRounds> batch_a{};
        std::array<uint32_t, kRounds> batch_b{};
        int64_t median_a_ns = 0;
        int64_t median_b_ns = 0;
        int64_t median_delta_ns = 0;
    };
    struct Result {
        Report report;
        common::ChildOutcome child;
    };

    struct CacheStats {
        std::array<uint32_t, kCpuLimit> lookups{};
        unsigned rows = 0;
    };
    struct CpuMask {
        std::array<bool, kCpuLimit> possible{};
        unsigned count = 0;
    };
    // Each returns 0 or the errno that says why the text was rejected.
    int parse_cache_stats(const char *text, size_t length, CacheStats &stats);
    int parse_cpu_list(const char *text, size_t length, CpuMask &mask);
    // The cache_stats row of a CPU, or -1 when the CPU is not possible.
    int stats_row(const CpuMask &mask, int cpu);

    // IO adapter (avc_lookup_io.cpp). Each call targets the calling thread and returns 0 or errno.
    int read_identity(char *context, unsigned capacity);
    int read_text(const char *path, char *buffer, size_t capacity, size_t &length);
    int open_attr(int &fd);
    WriteOutcome write_payload(int fd, const char *payload);
    void close_attr(int fd);
    int now_ns(uint64_t &value);
    int pin_to_allowed_cpu(int &cpu);
    // EXDEV when the thread runs elsewhere or its affinity is no longer exactly cpu.
    int verify_pinned(int cpu);

    Result collect();
}
#endif
