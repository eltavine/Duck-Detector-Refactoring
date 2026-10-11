// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/avc_lookup_probe.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sched.h>
#include <string>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace duckdetector::selinux::avc_lookup {
    namespace {
        struct Trial {
            ssize_t written = -1;
            int error = 0;
            int clock_error = 0;
            int64_t elapsed = 0;
        };

        bool rejected(const Trial &trial) {
            return trial.clock_error == 0 && trial.written == -1 && trial.error == EINVAL;
        }

        uint64_t clock_ns(int &error) {
            timespec time{};
            if (clock_gettime(CLOCK_MONOTONIC_RAW, &time) != 0) error = errno;
            return static_cast<uint64_t>(time.tv_sec) * 1000000000ULL + time.tv_nsec;
        }

        int64_t median(std::vector<int64_t> values) {
            std::sort(values.begin(), values.end());
            return values[(values.size() - 1) / 2];
        }
    }

    // Match SelinuxHideAttrProbe::run_app_zygote_probe's first experiment:
    // actual preload parent, scheduler-selected CPU, B/A preflight, direct write
    // bracketed by RAW timestamps, 32 warmups then 512 AB/BA pairs. In particular,
    // do not inherit the AVC counter experiment's fixed-CPU measurement contract.
    ParentTiming collect_parent_timing() {
        ParentTiming result;
        result.protocol = 1;
        result.pid = getpid();
        result.cpu = sched_getcpu(); // Entry CPU only; this experiment does not pin affinity.
        const uid_t uid = getuid();
        char initial[128]{};
        if ((result.error = read_identity(initial, sizeof(initial)))) return result;
        constexpr size_t prefix = sizeof(kCarrier) - 1;
        if (uid < 10000 || std::strncmp(initial, kCarrier, prefix) != 0 ||
            (initial[prefix] != '\0' && !(initial[prefix] == ':' && initial[prefix + 1] == 'c' &&
              initial[prefix + 2] >= '0' && initial[prefix + 2] <= '9'))) {
            result.error = EPERM;
            return result;
        }
        char mode[8];
        size_t length = 0;
        if ((result.error = read_text(kEnforce, mode, sizeof(mode), length))) return result;
        if (!length || mode[0] != '1') {
            result.error = EPERM;
            return result;
        }
        // The PoC reads this before timing but does not require readable counters.
        char stats[32768];
        read_text(kStats, stats, sizeof(stats), length);
        const std::string a = kPayloadA;
        std::string b = a;
        b[0] = '\n';
        std::vector<int64_t> times_a, times_b, deltas;
        times_a.reserve(kPairs);
        times_b.reserve(kPairs);
        deltas.reserve(kPairs);
        struct Attr {
            int fd = -1;
            ~Attr() { if (fd >= 0) close_attr(fd); }
        } attr;
        if ((result.error = open_attr(attr.fd))) return result;
        const auto trial = [&](const std::string &payload) {
            Trial t;
            errno = 0;
            const uint64_t begin = clock_ns(t.clock_error);
            if (t.clock_error) return t;
            t.written = write(attr.fd, payload.data(), payload.size());
            const int saved = errno;
            const uint64_t end = clock_ns(t.clock_error);
            t.error = t.written == -1 ? saved : 0;
            if (end < begin) t.clock_error = ERANGE;
            else t.elapsed = static_cast<int64_t>(end - begin);
            return t;
        };
        const auto accept = [&](const Trial &t) {
            if (rejected(t)) return true;
            result.error = t.clock_error ? t.clock_error : t.written == -1 ? t.error : EPROTO;
            return false;
        };
        if (!accept(trial(b)) || !accept(trial(a))) return result;
        for (int i = -static_cast<int>(kWarmup); i < static_cast<int>(kPairs); ++i) {
            const int before = sched_getcpu();
            Trial ta, tb;
            if ((i & 1) == 0) {
                ta = trial(a);
                if (!accept(ta)) break;
                tb = trial(b);
                if (!accept(tb)) break;
            } else {
                tb = trial(b);
                if (!accept(tb)) break;
                ta = trial(a);
                if (!accept(ta)) break;
            }
            if (i < 0) continue;
            const int after = sched_getcpu();
            if (before < 0 || after < 0 || before != after) {
                ++result.migrations;
                continue;
            }
            times_a.push_back(ta.elapsed);
            times_b.push_back(tb.elapsed);
            deltas.push_back(ta.elapsed - tb.elapsed);
        }
        result.pairs = deltas.size();
        result.a_slower = std::count_if(deltas.begin(), deltas.end(), [](int64_t d) { return d > 0; });
        for (size_t i = 0; i + kBlockPairs <= deltas.size(); i += kBlockPairs) {
            const int64_t block = median({deltas.begin() + i, deltas.begin() + i + kBlockPairs});
            if (block > 0) ++result.positive_blocks;
            else if (block < 0) ++result.negative_blocks;
            else ++result.zero_blocks;
        }
        if (!deltas.empty()) {
            result.medians_available = true;
            result.median_a_ns = median(times_a);
            result.median_b_ns = median(times_b);
            result.median_delta_ns = median(deltas);
        }
        char current[128]{};
        const int identity_error = read_identity(current, sizeof(current));
        if (identity_error) result.error = identity_error;
        else if (getuid() != uid || std::strcmp(initial, current) != 0) result.error = EPROTO;
        if (!result.error && (result.pairs != kPairs || result.migrations)) result.error = EAGAIN;
        result.complete = result.error == 0 && result.medians_available;
        return result;
    }
}
