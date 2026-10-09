/*
 * Copyright 2026 Duck Apps Contributor
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "selinux/attr_timing_probe.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <string>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace duckdetector::selinux {
namespace {
    constexpr char kCurrent[] = "/proc/thread-self/attr/current";
    constexpr int kWarmupPairs = 32;
    constexpr int kMeasuredPairs = 256;

    uint64_t monotonic_raw_ns() {
        timespec t{};
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &t) != 0) return 0;
        return static_cast<uint64_t>(t.tv_sec) * 1000000000ULL + t.tv_nsec;
    }

    struct WriteResult {
        int open_error = 0;
        int write_error = 0;
        ssize_t bytes = -1;
        int64_t nanos = 0;

        bool expected_denial() const {
            return open_error == 0 && bytes == -1 && write_error == EACCES && nanos > 0;
        }
    };

    WriteResult sample(const std::string& payload) {
        WriteResult result;
        const int fd = open(kCurrent, O_WRONLY | O_CLOEXEC);
        if (fd < 0) {
            result.open_error = errno;
            return result;
        }
        errno = 0;
        const uint64_t before = monotonic_raw_ns();
        if (before != 0) {
            result.bytes = write(fd, payload.data(), payload.size());
            const int saved_errno = errno;
            const uint64_t after = monotonic_raw_ns();
            result.write_error = result.bytes == -1 ? saved_errno : 0;
            if (after >= before) result.nanos = static_cast<int64_t>(after - before);
        }
        close(fd);
        return result;
    }

    int64_t percentile(std::vector<int64_t> values, size_t pct) {
        std::sort(values.begin(), values.end());
        return values[(values.size() - 1) * pct / 100];
    }

    std::string stop(const std::string& why) {
        return "STATE=UNAVAILABLE\nREASON=" + why + "\n";
    }

    std::string describe_failure(const char* side, const WriteResult& result) {
        std::ostringstream out;
        out << side << " unexpected open_errno=" << result.open_error
            << " write_errno=" << result.write_error << " returned=" << result.bytes
            << " duration_ns=" << result.nanos;
        return out.str();
    }
}

std::string collect_attr_timing_probe() {
    // This probe never requests root. Do not attempt a context change from
    // privileged processes that could actually possess SETCURRENT.
    if (getuid() < 10000) return stop("Non-app UID");

    const int read_fd = open(kCurrent, O_RDONLY | O_CLOEXEC);
    if (read_fd < 0) return stop("Cannot read thread-self attr/current, errno=" + std::to_string(errno));
    char buffer[512]{};
    const ssize_t count = read(read_fd, buffer, sizeof(buffer));
    const int read_error = errno;
    close(read_fd);
    if (count <= 1 || count >= static_cast<ssize_t>(sizeof(buffer)))
        return stop("Invalid context length or read errno=" + std::to_string(read_error));

    std::string a(buffer, static_cast<size_t>(count));
    while (!a.empty() && (a.back() == '\n' || a.back() == '\0')) a.pop_back();
    if (a.size() < 5 || a.find('\0') != std::string::npos || a.rfind("u:r:", 0) != 0)
        return stop("Current thread context is not a normal application domain");

    // Match the independently tested PoC byte-for-byte: the first byte alone
    // differs and the payload sizes remain identical. /proc/thread-self is
    // necessary to pass proc_pid_attr_write's current == task guard.
    std::string b = a;
    b[0] = '\n';

    // Guard before any valid-context write: both operations MUST fail with
    // EACCES. Never continue sampling if the device unexpectedly allows one.
    const WriteResult pre_b = sample(b);
    if (!pre_b.expected_denial()) return stop(describe_failure("B preflight", pre_b));
    const WriteResult pre_a = sample(a);
    if (!pre_a.expected_denial()) return stop(describe_failure("A preflight", pre_a));

    std::vector<int64_t> a_ns, b_ns, delta;
    a_ns.reserve(kMeasuredPairs);
    b_ns.reserve(kMeasuredPairs);
    delta.reserve(kMeasuredPairs);
    int positive = 0;
    for (int i = -kWarmupPairs; i < kMeasuredPairs; ++i) {
        WriteResult x, y;
        if ((i & 1) == 0) {
            x = sample(a);
            if (!x.expected_denial()) return stop(describe_failure("A", x));
            y = sample(b);
        } else {
            y = sample(b);
            if (!y.expected_denial()) return stop(describe_failure("B", y));
            x = sample(a);
        }
        if (!x.expected_denial() || !y.expected_denial())
            return stop(describe_failure(!x.expected_denial() ? "A" : "B", !x.expected_denial() ? x : y));
        if (i < 0) continue;
        a_ns.push_back(x.nanos);
        b_ns.push_back(y.nanos);
        delta.push_back(x.nanos - y.nanos);
        if (x.nanos > y.nanos) ++positive;
    }

    const int64_t median_delta = percentile(delta, 50);
    const int64_t first_half = percentile(std::vector<int64_t>(delta.begin(), delta.begin() + kMeasuredPairs / 2), 50);
    const int64_t second_half = percentile(std::vector<int64_t>(delta.begin() + kMeasuredPairs / 2, delta.end()), 50);
    // An experimental, device-local signal. A fixed cross-device KSU verdict
    // would be unsupported: timing depends on hardware, policy and OEM code.
    const bool candidate = median_delta > 400 && first_half > 400 && second_half > 400 &&
                           positive >= (kMeasuredPairs * 9 / 10);

    std::ostringstream out;
    out << "STATE=" << (candidate ? "CANDIDATE" : "NO_SIGNAL") << '\n'
        << "PAIRS=" << kMeasuredPairs << '\n'
        << "A_MEDIAN_NS=" << percentile(a_ns, 50) << '\n'
        << "B_MEDIAN_NS=" << percentile(b_ns, 50) << '\n'
        << "DELTA_P10_NS=" << percentile(delta, 10) << '\n'
        << "DELTA_MEDIAN_NS=" << median_delta << '\n'
        << "DELTA_P90_NS=" << percentile(delta, 90) << '\n'
        << "HALVES_NS=" << first_half << ',' << second_half << '\n'
        << "A_SLOWER=" << positive << '\n'
        << "CONTEXT_LENGTH=" << a.size() << '\n'
        << "ERRORS=both EACCES\n";
    return out.str();
}

}  // namespace duckdetector::selinux
