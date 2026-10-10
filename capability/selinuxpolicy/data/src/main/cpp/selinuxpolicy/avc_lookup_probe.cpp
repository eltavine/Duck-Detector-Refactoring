// SPDX-License-Identifier: Apache-2.0
// Experimental app_zygote AVC lookup measurement. No root, hidden APIs, or
// valid SELinux transitions. A disposable child owns every attempted write.
#include "common/disposable_child.h"
#include <jni.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sched.h>
#include <string>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <array>

namespace duckdetector::selinux::avc_lookup {
namespace {
constexpr char kAttr[] = "/proc/thread-self/attr/current";
constexpr char kStats[] = "/sys/fs/selinux/avc/cache_stats";
constexpr char kEnforce[] = "/sys/fs/selinux/enforce";
constexpr char kInvalid[] = "u:r:__selinux_hide_probe_invalid__:s0";
constexpr unsigned kPairs = 128;
constexpr unsigned kWarmup = 32;
constexpr unsigned kRounds = 4;
constexpr unsigned kWrites = 4096;
constexpr unsigned kCpuLimit = 256;

enum class State : int { kUnavailable, kUnsupported, kPermissionLimited, kTimingOnly, kCollected, kInconclusive };
struct Report {
    State state = State::kUnavailable;
    int error = 0;
    int stats_error = 0;
    int cpu = -1;
    int rows = 0;
    unsigned pairs = 0;
    unsigned rounds = 0;
    int profile = 0; // 0=unclassified, 1=A1/B2, 2=A2/B2, 3=A1/B1
    uint64_t lookups_a = 0;
    uint64_t lookups_b = 0;
    uint32_t batch_a[kRounds]{};
    uint32_t batch_b[kRounds]{};
    int64_t a_median_ns = 0;
    int64_t b_median_ns = 0;
    int64_t delta_median_ns = 0;
};
struct Result { Report report; common::ChildOutcome child; };

uint64_t now_ns() {
    timespec t{};
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return static_cast<uint64_t>(t.tv_sec) * 1000000000ULL + t.tv_nsec;
}

// Return a separate open error and write error. A successful or short write
// must abort the experiment, even with an intentionally invalid context.
int write_invalid(const int fd, const char *data, const size_t length) {
    const ssize_t n = write(fd, data, length);
    return n == -1 ? errno : EPROTO;
}

bool read_domain(char (&domain)[128]) {
    const int fd = open(kAttr, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    const ssize_t n = read(fd, domain, sizeof(domain) - 1);
    close(fd);
    if (n < 1 || n >= static_cast<ssize_t>(sizeof(domain) - 1)) return false;
    domain[n] = '\0';
    for (ssize_t i = n - 1; i >= 0 && (domain[i] == '\n' || domain[i] == '\0'); --i)
        domain[i] = '\0';
    return strncmp(domain, "u:r:app_zygote:s0", sizeof("u:r:app_zygote:s0") - 1) == 0 &&
           (domain[sizeof("u:r:app_zygote:s0") - 1] == '\0' ||
            domain[sizeof("u:r:app_zygote:s0") - 1] == ':');
}

struct Counters {
    uint32_t lookup[kCpuLimit]{};
    unsigned rows = 0;
    int error = 0;
};

bool digits(const char *&p, const char *end, uint32_t &out) {
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    if (p == end || *p < '0' || *p > '9') return false;
    uint64_t value = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        value = value * 10 + static_cast<unsigned>(*p - '0');
        if (value > UINT32_MAX) return false;
        ++p;
    }
    out = static_cast<uint32_t>(value);
    return true;
}

// ACK selinuxfs prints one row per possible CPU, with 'lookups' as the first
// numeric column. Reject unexpected formats instead of fabricating counts.
Counters read_counters() {
    Counters out;
    const int fd = open(kStats, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { out.error = errno; return out; }
    char buffer[16384];
    size_t used = 0;
    while (used < sizeof(buffer)) {
        const ssize_t n = read(fd, buffer + used, sizeof(buffer) - used);
        if (n == -1 && errno == EINTR) continue;
        if (n == -1) { out.error = errno; break; }
        if (n == 0) break;
        used += static_cast<size_t>(n);
    }
    close(fd);
    if (out.error) return out;
    if (used == sizeof(buffer)) { out.error = EOVERFLOW; return out; }
    const char *p = buffer, *end = buffer + used;
    const char *header = static_cast<const char *>(memchr(p, '\n', end - p));
    if (!header || static_cast<size_t>(header - p) < 7 ||
        !memmem(p, header - p, "lookups", 7)) { out.error = EPROTO; return out; }
    p = header + 1;
    while (p < end) {
        const char *line = static_cast<const char *>(memchr(p, '\n', end - p));
        if (!line) { out.error = EPROTO; return out; }
        if (line == p) { p = line + 1; continue; }
        if (out.rows >= kCpuLimit || !digits(p, line, out.lookup[out.rows])) {
            out.error = EPROTO;
            return out;
        }
        ++out.rows;
        p = line + 1;
    }
    if (!out.rows) out.error = ENODATA;
    return out;
}

int select_cpu() {
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (syscall(SYS_sched_getaffinity, 0, sizeof(allowed), &allowed) < 0) return -1;
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (!CPU_ISSET(i, &allowed)) continue;
        cpu_set_t target;
        CPU_ZERO(&target);
        CPU_SET(i, &target);
        if (syscall(SYS_sched_setaffinity, 0, sizeof(target), &target) == 0) return i;
    }
    return -1;
}

void median_sort(int64_t (&values)[kPairs], const unsigned count) {
    // No heap allocation or non-fork-safe C++ library calls inside the child.
    for (unsigned i = 1; i < count; ++i) {
        const int64_t v = values[i];
        unsigned j = i;
        while (j && values[j - 1] > v) { values[j] = values[j - 1]; --j; }
        values[j] = v;
    }
}

int run_child(int report_fd) {
    Report r;
    char initial[128]{};
    if (getuid() < 10000 || !read_domain(initial)) { r.state = State::kUnsupported; goto finish; }
    {
        const int enforce_fd = open(kEnforce, O_RDONLY | O_CLOEXEC);
        if (enforce_fd < 0) { r.error = errno; r.state = State::kUnavailable; goto finish; }
        char mode = 0;
        const ssize_t n = read(enforce_fd, &mode, 1);
        close(enforce_fd);
        if (n != 1 || mode != '1') { r.state = State::kUnsupported; goto finish; }
    }
    {
        const int fd = open(kAttr, O_WRONLY | O_CLOEXEC);
        if (fd < 0) { r.state = State::kPermissionLimited; r.error = errno; goto finish; }
        char b[sizeof(kInvalid)]{};
        memcpy(b, kInvalid, sizeof(kInvalid));
        b[0] = '\n';
        const size_t length = sizeof(kInvalid) - 1;
        const int control_b = write_invalid(fd, b, length);
        const int control_a = control_b == EINVAL ? write_invalid(fd, kInvalid, length) : control_b;
        if (control_a != EINVAL || control_b != EINVAL) {
            r.error = control_a != EINVAL ? control_a : control_b;
            r.state = r.error == EACCES || r.error == EPERM
                          ? State::kPermissionLimited : State::kInconclusive;
            close(fd);
            goto finish;
        }
        int64_t a[kPairs]{}, btime[kPairs]{}, delta[kPairs]{};
        for (unsigned i = 0; i < kPairs + kWarmup; ++i) {
            const bool a_first = (i & 1) == 0;
            const char *first = a_first ? kInvalid : b;
            const char *second = a_first ? b : kInvalid;
            const uint64_t t0 = now_ns();
            const int e0 = write_invalid(fd, first, length);
            const uint64_t t1 = now_ns();
            const int e1 = e0 == EINVAL ? write_invalid(fd, second, length) : e0;
            const uint64_t t2 = now_ns();
            if (e0 != EINVAL || e1 != EINVAL || !t0 || t1 < t0 || t2 < t1) {
                r.error = e0 != EINVAL ? e0 : e1;
                r.state = State::kInconclusive;
                close(fd);
                goto finish;
            }
            if (i >= kWarmup) {
                const unsigned j = i - kWarmup;
                a[j] = static_cast<int64_t>(a_first ? t1 - t0 : t2 - t1);
                btime[j] = static_cast<int64_t>(a_first ? t2 - t1 : t1 - t0);
                delta[j] = a[j] - btime[j];
                ++r.pairs;
            }
        }
        median_sort(a, kPairs);
        median_sort(btime, kPairs);
        median_sort(delta, kPairs);
        r.a_median_ns = a[kPairs / 2];
        r.b_median_ns = btime[kPairs / 2];
        r.delta_median_ns = delta[kPairs / 2];
        r.state = State::kTimingOnly;

        // Count collection is optional; a readable cache_stats file is a
        // permission/CONFIG-dependent capability, not guaranteed by AOSP.
        r.cpu = select_cpu();
        if (r.cpu < 0 || r.cpu >= static_cast<int>(kCpuLimit)) {
            r.stats_error = EOPNOTSUPP;
        } else {
            const Counters test = read_counters();
            r.stats_error = test.error;
            if (!test.error && test.rows > static_cast<unsigned>(r.cpu)) {
                r.rows = static_cast<int>(test.rows);
                for (unsigned round = 0; round < kRounds; ++round) {
                    for (unsigned order = 0; order < 2; ++order) {
                        const bool is_a = ((round + order) & 1) == 0;
                        const char *payload = is_a ? kInvalid : b;
                        const Counters before = read_counters();
                        if (before.error || before.rows != test.rows) {
                            r.stats_error = before.error ? before.error : EPROTO;
                            break;
                        }
                        unsigned j = 0;
                        for (; j < kWrites; ++j) {
                            if (write_invalid(fd, payload, length) != EINVAL) {
                                r.stats_error = EPROTO;
                                break;
                            }
                        }
                        if (r.stats_error) break;
                        const Counters after = read_counters();
                        if (after.error || after.rows != before.rows) {
                            r.stats_error = after.error ? after.error : EPROTO;
                            break;
                        }
                        unsigned cpu_now = UINT32_MAX;
                        if (syscall(SYS_getcpu, &cpu_now, nullptr, nullptr) != 0 ||
                            cpu_now != static_cast<unsigned>(r.cpu)) {
                            r.stats_error = EXDEV;
                            break;
                        }
                        const uint32_t difference = after.lookup[r.cpu] - before.lookup[r.cpu];
                        if (is_a) { r.lookups_a += difference; r.batch_a[round] = difference; }
                        else { r.lookups_b += difference; r.batch_b[round] = difference; }
                    }
                    if (r.stats_error) break;
                    ++r.rounds;
                }
                if (!r.stats_error && r.rounds == kRounds) {
                    r.state = State::kCollected;
                    bool a_one = true, a_two = true, b_one = true, b_two = true;
                    for (unsigned i = 0; i < kRounds; ++i) {
                        const uint32_t a = r.batch_a[i], bcount = r.batch_b[i];
                        a_one &= a >= kWrites && a <= kWrites * 11 / 10;
                        a_two &= a >= 2 * kWrites && a <= kWrites * 21 / 10;
                        b_one &= bcount >= kWrites && bcount <= kWrites * 11 / 10;
                        b_two &= bcount >= 2 * kWrites && bcount <= kWrites * 21 / 10;
                    }
                    if (a_one && b_two) r.profile = 1;
                    else if (a_two && b_two) r.profile = 2;
                    else if (a_one && b_one) r.profile = 3;
                }
            } else if (!test.error) {
                r.stats_error = EPROTO;
            }
        }
        close(fd);
    }
    {
        char current[128]{};
        if (!read_domain(current) || strcmp(initial, current) != 0) {
            r.state = State::kInconclusive;
            r.error = EPROTO;
        }
    }
finish:
    const ssize_t written = write(report_fd, &r, sizeof(r));
    return written == sizeof(r) ? 0 : 1;
}

Result collect() {
    Result result{};
    std::array<unsigned char, sizeof(Report)> report{};
    result.child = common::run_disposable_child(report,
            {std::chrono::milliseconds(2000), std::chrono::milliseconds(250)},
            [](int fd) { return run_child(fd); });
    if (result.child.end == common::ChildEnd::kExited &&
        result.child.exit_status == 0 && result.child.report_length == sizeof(Report)) {
        memcpy(&result.report, report.data(), sizeof(Report));
    } else {
        result.report.state = State::kUnavailable;
        result.report.error = result.child.error ? result.child.error : EIO;
    }
    return result;
}

} // namespace
} // namespace duckdetector::selinux::avc_lookup

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxAvcLookupProbe_nativeCollectAvcLookup(
        JNIEnv *env, jobject) {
    const auto result = duckdetector::selinux::avc_lookup::collect();
    const auto &r = result.report;
    const char *state = "INCONCLUSIVE";
    switch (r.state) {
        case duckdetector::selinux::avc_lookup::State::kUnavailable: state = "UNAVAILABLE"; break;
        case duckdetector::selinux::avc_lookup::State::kUnsupported: state = "UNSUPPORTED"; break;
        case duckdetector::selinux::avc_lookup::State::kPermissionLimited: state = "PERMISSION_LIMITED"; break;
        case duckdetector::selinux::avc_lookup::State::kTimingOnly: state = "TIMING_ONLY"; break;
        case duckdetector::selinux::avc_lookup::State::kCollected: state = "COLLECTED"; break;
        case duckdetector::selinux::avc_lookup::State::kInconclusive: state = "INCONCLUSIVE"; break;
    }
    char buffer[860]{};
    snprintf(buffer, sizeof(buffer),
             "SCHEMA=1\nSTATE=%s\nERROR=%d\nSTATS_ERROR=%d\nCPU=%d\nROWS=%d\nPAIRS=%u\nROUNDS=%u\nPROFILE=%d\nWRITES=%u\nLOOKUPS_A=%llu\nLOOKUPS_B=%llu\nBATCH_A=%u,%u,%u,%u\nBATCH_B=%u,%u,%u,%u\nMEDIAN_A_NS=%lld\nMEDIAN_B_NS=%lld\nMEDIAN_DELTA_NS=%lld\nCHILD_END=%d\n",
             state, r.error, r.stats_error, r.cpu, r.rows, r.pairs, r.rounds, r.profile,
             duckdetector::selinux::avc_lookup::kWrites,
             static_cast<unsigned long long>(r.lookups_a),
             static_cast<unsigned long long>(r.lookups_b),
             r.batch_a[0], r.batch_a[1], r.batch_a[2], r.batch_a[3],
             r.batch_b[0], r.batch_b[1], r.batch_b[2], r.batch_b[3],
             static_cast<long long>(r.a_median_ns), static_cast<long long>(r.b_median_ns),
             static_cast<long long>(r.delta_median_ns), static_cast<int>(result.child.end));
    return env->NewStringUTF(buffer);
}
