// SPDX-License-Identifier: Apache-2.0
// Per-CPU AVC lookups and timing of rejected attr/current writes, measured in a disposable child
// of the app_zygote preload. The payloads never pass conversion, so they register no context.
#include "selinuxpolicy/avc_lookup_probe.h"
#include <cerrno>
#include <cstring>
#include <unistd.h>

namespace duckdetector::selinux::avc_lookup {
    namespace {
        // A normal run takes well under a second; slow cores and a hooked handler get headroom.
        constexpr common::ChildDeadlines kDeadlines{std::chrono::milliseconds(2000), std::chrono::milliseconds(250)};
        // One record per step and per counted round plus the last one is 13; a full buffer means
        // records were dropped, so the last kept record would not be the child's final one.
        constexpr unsigned kRecordCapacity = 16;
        // The header line and 256 rows of six 10-digit columns.
        constexpr size_t kStatsCapacity = 48 + kCpuLimit * 66;
        constexpr char kStatsHeader[] = "lookups hits misses allocations reclaims frees\n";

        bool number(const char *&cursor, const char *end, uint32_t &value) {
            if (cursor == end || *cursor < '0' || *cursor > '9') return false;
            uint64_t parsed = 0;
            for (; cursor < end && *cursor >= '0' && *cursor <= '9'; ++cursor) {
                parsed = parsed * 10 + static_cast<unsigned>(*cursor - '0');
                if (parsed > UINT32_MAX) return false;
            }
            value = static_cast<uint32_t>(parsed);
            return true;
        }

        bool rejected(const WriteOutcome &outcome) { return outcome.bytes == -1 && outcome.error == EINVAL; }

        // AOSP seapp_contexts derives app_zygote MLS categories from the app/user UID.
        // Accept categories after the fixed context boundary; later identity checks compare
        // the full captured label, so changing only the categories still invalidates the run.
        bool is_carrier(const char *context) {
            constexpr size_t fixed = sizeof(kCarrier) - 1;
            if (std::strncmp(context, kCarrier, fixed) != 0) return false;
            return context[fixed] == '\0' ||
                   (context[fixed] == ':' && context[fixed + 1] == 'c' &&
                    context[fixed + 2] >= '0' && context[fixed + 2] <= '9');
        }

        struct Session {
            Report report;
            int report_fd = -1;
            int attr = -1;
            bool lost = false;

            void publish() {
                const auto *data = reinterpret_cast<const unsigned char *>(&report);
                size_t sent = 0;
                while (!lost && sent < sizeof(report)) {
                    const ssize_t count = write(report_fd, data + sent, sizeof(report) - sent);
                    if (count < 0 && errno == EINTR) continue;
                    if (count <= 0) lost = true;
                    else sent += static_cast<size_t>(count);
                }
            }

            void advance(const Step step) {
                report.step = step;
                publish();
            }

            // Success or a short write means a handler accepted a label that names no type, and any
            // other errno means the payload left the measured path; neither leaves counts to compare.
            bool issue(const Payload payload) {
                const WriteOutcome outcome = write_payload(attr, payload == Payload::kA ? kPayloadA : kPayloadB);
                if (rejected(outcome)) return true;
                report.unexpected = payload;
                report.unexpected_bytes = outcome.bytes;
                report.error = outcome.bytes == -1 ? outcome.error : 0;
                report.state = State::kInconclusive;
                return false;
            }

            // Counters stay uncollected; the completed timing remains valid.
            bool stats_failed(const int error) {
                report.error = error;
                return false;
            }
        };

        void sort(std::array<int64_t, kPairs> &values) {
            // Insertion sort: the child may not allocate or call library code that is not async-signal-safe.
            for (unsigned i = 1; i < kPairs; ++i) {
                const int64_t value = values[i];
                unsigned j = i;
                for (; j > 0 && values[j - 1] > value; --j) values[j] = values[j - 1];
                values[j] = value;
            }
        }

        bool time_pairs(Session &session) {
            auto &report = session.report;
            std::array<int64_t, kPairs> a{}, b{}, delta{};
            for (unsigned i = 0; i < kWarmup + kPairs; ++i) {
                const bool a_first = (i & 1u) == 0;
                uint64_t start = 0, middle = 0, end = 0;
                int error = now_ns(start);
                if (!session.issue(a_first ? Payload::kA : Payload::kB)) return false;
                if (!error) error = now_ns(middle);
                if (!session.issue(a_first ? Payload::kB : Payload::kA)) return false;
                if (!error) error = now_ns(end);
                if (error || middle < start || end < middle) {
                    report.error = error ? error : ERANGE;
                    report.state = State::kInconclusive;
                    return false;
                }
                if (i < kWarmup) continue;
                const auto first = static_cast<int64_t>(middle - start);
                const auto second = static_cast<int64_t>(end - middle);
                const unsigned pair = i - kWarmup;
                a[pair] = a_first ? first : second;
                b[pair] = a_first ? second : first;
                delta[pair] = a[pair] - b[pair];
                ++report.pairs;
            }
            sort(a);
            sort(b);
            sort(delta);
            report.median_a_ns = a[kPairs / 2];
            report.median_b_ns = b[kPairs / 2];
            report.median_delta_ns = delta[kPairs / 2];
            return true;
        }

        int read_stats(CacheStats &stats) {
            char text[kStatsCapacity];
            size_t length = 0;
            if (const int error = read_text(kStats, text, sizeof(text), length)) return error;
            return parse_cache_stats(text, length, stats);
        }

        // Each batch lies between two reads of the pinned CPU's row. The counter is shared by every
        // task on that CPU, so other work and the second read's own path walk can only add to it.
        bool count_batch(Session &session, const Payload payload, uint32_t &lookups) {
            auto &report = session.report;
            CacheStats before, after;
            if (const int error = verify_pinned(report.cpu)) return session.stats_failed(error);
            if (const int error = read_stats(before)) return session.stats_failed(error);
            if (before.rows != report.cpu_rows) return session.stats_failed(EPROTO);
            for (unsigned i = 0; i < kWrites; ++i) {
                if (!session.issue(payload)) return false;
            }
            if (const int error = read_stats(after)) return session.stats_failed(error);
            if (after.rows != report.cpu_rows) return session.stats_failed(EPROTO);
            if (const int error = verify_pinned(report.cpu)) return session.stats_failed(error);
            lookups = after.lookups[report.cpu_row] - before.lookups[report.cpu_row];
            return true;
        }

        bool count_rounds(Session &session) {
            auto &report = session.report;
            session.advance(Step::kAffinity);
            if (const int error = pin_to_allowed_cpu(report.cpu)) return session.stats_failed(error);
            session.advance(Step::kCpuMap);
            char list[1024];
            size_t length = 0;
            CpuMask mask;
            if (const int error = read_text(kPossibleCpus, list, sizeof(list), length)) return session.stats_failed(error);
            if (const int error = parse_cpu_list(list, length, mask)) return session.stats_failed(error);
            report.possible_cpus = mask.count;
            report.cpu_row = stats_row(mask, report.cpu);
            if (report.cpu_row < 0) return session.stats_failed(EDOM);
            session.advance(Step::kStats);
            CacheStats stats;
            if (const int error = read_stats(stats)) return session.stats_failed(error);
            report.cpu_rows = stats.rows;
            // sel_avc_get_stat_idx prints one row per possible CPU; any other count leaves the row unknown.
            if (stats.rows != mask.count) return session.stats_failed(EPROTO);
            session.advance(Step::kCounting);
            for (unsigned round = 0; round < kRounds; ++round) {
                // AB, BA, AB, BA: order effects and slow drift fall on both payloads alike.
                for (unsigned order = 0; order < 2; ++order) {
                    const bool a = ((round + order) & 1u) == 0;
                    if (!count_batch(session, a ? Payload::kA : Payload::kB,
                                     a ? report.batch_a[round] : report.batch_b[round])) return false;
                }
                ++report.rounds;
                session.publish();
            }
            return true;
        }

        int run_child(const int report_fd) {
            Session session;
            session.report_fd = report_fd;
            auto &report = session.report;
            const uid_t uid = getuid();
            char initial[128]{};
            report.error = read_identity(initial, sizeof(initial));
            if (report.error || uid < 10000 || !is_carrier(initial)) {
                report.state = report.error ? State::kUnavailable : State::kUnsupported;
                session.publish();
                return session.lost ? 1 : 0;
            }
            session.advance(Step::kEnforce);
            char mode[8];
            size_t length = 0;
            report.error = read_text(kEnforce, mode, sizeof(mode), length);
            if (report.error || length == 0 || mode[0] != '1') {
                report.state = report.error ? State::kUnavailable : State::kUnsupported;
                session.publish();
                return session.lost ? 1 : 0;
            }
            session.advance(Step::kOpen);
            report.error = open_attr(session.attr);
            if (report.error) {
                report.state = report.error == EACCES || report.error == EPERM
                               ? State::kPermissionLimited : State::kUnavailable;
                session.publish();
                return session.lost ? 1 : 0;
            }
            session.advance(Step::kControls);
            if (!session.issue(Payload::kA) || !session.issue(Payload::kB)) {
                // A refused SETCURRENT check fails before conversion; the measured path is out of reach.
                if (report.unexpected_bytes == -1 && (report.error == EACCES || report.error == EPERM))
                    report.state = State::kPermissionLimited;
            } else {
                session.advance(Step::kTiming);
                if (time_pairs(session)) {
                    report.state = State::kTimingOnly;
                    if (count_rounds(session)) report.state = State::kCollected;
                }
            }
            close_attr(session.attr);
            char current[128]{};
            const int identity_error = read_identity(current, sizeof(current));
            const bool changed = identity_error == 0 && (getuid() != uid || std::strcmp(current, initial) != 0);
            if (identity_error || changed) {
                report.identity_changed = changed;
                // The first failure keeps its step and errno.
                if (report.state != State::kInconclusive) {
                    report.state = State::kInconclusive;
                    report.step = Step::kIdentity;
                    report.error = identity_error;
                }
            }
            if (report.state == State::kCollected) report.step = Step::kFinished;
            session.publish();
            return session.lost ? 1 : 0;
        }
    }

    // ACK selinuxfs (sel_avc_stats_seq_show) prints this header and then, for each possible CPU in
    // ascending order, "%u %u %u %u %u %u\n" with hits computed as lookups - misses.
    int parse_cache_stats(const char *text, const size_t length, CacheStats &stats) {
        stats = CacheStats{};
        constexpr size_t header = sizeof(kStatsHeader) - 1;
        if (length < header || std::memcmp(text, kStatsHeader, header) != 0) return EPROTO;
        const char *cursor = text + header;
        const char *const end = text + length;
        while (cursor < end) {
            if (stats.rows == kCpuLimit) return E2BIG;
            uint32_t columns[6];
            for (unsigned column = 0; column < 6; ++column) {
                if (!number(cursor, end, columns[column])) return EPROTO;
                if (cursor == end || *cursor != (column == 5 ? '\n' : ' ')) return EPROTO;
                ++cursor;
            }
            // A row whose hits and misses do not add up to its first column is not this format.
            if (static_cast<uint32_t>(columns[1] + columns[2]) != columns[0]) return EPROTO;
            stats.lookups[stats.rows++] = columns[0];
        }
        return stats.rows > 0 ? 0 : ENODATA;
    }

    // drivers/base/cpu.c prints cpu_possible_mask as a cpulist: ascending "n" or "n-m" items joined
    // by commas and ended by a newline.
    int parse_cpu_list(const char *text, const size_t length, CpuMask &mask) {
        mask = CpuMask{};
        const char *cursor = text;
        const char *const end = text + length;
        int64_t previous = -1;
        while (true) {
            uint32_t first = 0;
            if (!number(cursor, end, first)) return EPROTO;
            uint32_t last = first;
            if (cursor < end && *cursor == '-') {
                ++cursor;
                if (!number(cursor, end, last)) return EPROTO;
            }
            if (static_cast<int64_t>(first) <= previous || last < first) return EPROTO;
            if (last >= kCpuLimit) return E2BIG;
            for (uint32_t cpu = first; cpu <= last; ++cpu) mask.possible[cpu] = true;
            mask.count += last - first + 1;
            previous = last;
            if (cursor == end || *cursor != ',') break;
            ++cursor;
        }
        if (cursor < end && *cursor == '\n') ++cursor;
        return cursor == end ? 0 : EPROTO;
    }

    int stats_row(const CpuMask &mask, const int cpu) {
        if (cpu < 0 || cpu >= static_cast<int>(kCpuLimit) || !mask.possible[cpu]) return -1;
        int row = 0;
        for (int index = 0; index < cpu; ++index) row += mask.possible[index] ? 1 : 0;
        return row;
    }

    Result collect() {
        Result result;
        std::array<unsigned char, sizeof(Report) * kRecordCapacity> records{};
        result.child = common::run_disposable_child(records, kDeadlines, [](int fd) { return run_child(fd); });
        const size_t length = result.child.report_length;
        if (length >= sizeof(Report)) {
            std::memcpy(&result.report, records.data() + (length / sizeof(Report) - 1) * sizeof(Report), sizeof(Report));
        }
        const bool complete = result.child.end == common::ChildEnd::kExited && result.child.exit_status == 0 &&
                              length >= sizeof(Report) && length % sizeof(Report) == 0 && length < records.size();
        if (!complete) {
            result.report.state = result.child.end == common::ChildEnd::kNotStarted ||
                                  result.child.end == common::ChildEnd::kSetupFailed
                                  ? State::kUnavailable : State::kInconclusive;
            if (result.child.error) result.report.error = result.child.error;
        }
        return result;
    }
}
