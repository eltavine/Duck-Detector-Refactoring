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
        // One record per step and per counted round plus the last one is 14; a full buffer means
        // records were dropped, so the last kept record would not be the child's final one.
        constexpr unsigned kRecordCapacity = 16;
        // The header line and 256 rows of six 10-digit columns.
        constexpr size_t kStatsCapacity = 48 + kCpuLimit * 66;

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

        // The preload parent cannot safely probe an unknown kernel's attr/current handler:
        // a fault, seccomp trap, success or short write must terminate only this disposable child.
        // Unlike the full AVC child, this makes just two rejected writes and never pins a CPU.
        int parent_preflight_child(const int report_fd) {
            int error = 0;
            const uid_t uid = getuid();
            char initial[128]{};
            if ((error = read_identity(initial, sizeof(initial))) != 0) {
                // Keep the original errno.
            } else if (uid < 10000 || !is_carrier(initial)) {
                error = EPERM;
            } else {
                char mode[8]{};
                size_t length = 0;
                error = read_text(kEnforce, mode, sizeof(mode), length);
                if (!error && (!length || mode[0] != '1')) error = EPERM;
                if (!error) {
                    int fd = -1;
                    error = open_attr(fd);
                    if (!error) {
                        // PoC preflight order is B then A; both must be rejected as EINVAL.
                        const WriteOutcome b = write_payload(fd, kPayloadB);
                        if (!rejected(b)) error = b.bytes == -1 && b.error ? b.error : EPROTO;
                        if (!error) {
                            const WriteOutcome a = write_payload(fd, kPayloadA);
                            if (!rejected(a)) error = a.bytes == -1 && a.error ? a.error : EPROTO;
                        }
                        close_attr(fd);
                    }
                }
                char current[128]{};
                const int identity_error = read_identity(current, sizeof(current));
                if (identity_error) error = identity_error;
                else if (getuid() != uid || std::strcmp(initial, current) != 0) error = EPROTO;
            }
            // A complete 0-valued record is required; child exit status alone is insufficient.
            const auto *bytes = reinterpret_cast<const unsigned char *>(&error);
            size_t written = 0;
            while (written < sizeof(error)) {
                const ssize_t n = write(report_fd, bytes + written, sizeof(error) - written);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) return 1;
                written += static_cast<size_t>(n);
            }
            return error ? 1 : 0;
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

        template<size_t N>
        void sort(std::array<int64_t, N> &values, const unsigned count) {
            // Insertion sort: the child may not allocate or call library code that is not async-signal-safe.
            for (unsigned i = 1; i < count; ++i) {
                const int64_t value = values[i];
                unsigned j = i;
                for (; j > 0 && values[j - 1] > value; --j) values[j] = values[j - 1];
                values[j] = value;
            }
        }

        bool time_pairs(Session &session) {
            auto &report = session.report;
            std::array<int64_t, kPairs> a{}, b{}, delta{};
            // Read the clock on both sides of each write independently.
            // Reusing the first write's end timestamp as the second write's start would
            // include inter-trial userspace overhead only in the second duration.
            const auto timed_issue = [&session, &report](const Payload payload, int64_t &duration) {
                uint64_t start = 0, end = 0;
                if (const int error = now_ns(start)) {
                    report.error = error;
                    report.state = State::kInconclusive;
                    return false;
                }
                if (!session.issue(payload)) return false;
                if (const int error = now_ns(end)) {
                    report.error = error;
                    report.state = State::kInconclusive;
                    return false;
                }
                if (end < start) {
                    report.error = ERANGE;
                    report.state = State::kInconclusive;
                    return false;
                }
                duration = static_cast<int64_t>(end - start);
                return true;
            };
            for (unsigned i = 0; i < kWarmup + kPairs; ++i) {
                const bool a_first = (i & 1u) == 0;
                const int cpu_before = current_cpu();
                int64_t first = 0, second = 0;
                if (!timed_issue(a_first ? Payload::kA : Payload::kB, first) ||
                    !timed_issue(a_first ? Payload::kB : Payload::kA, second)) return false;
                if (i < kWarmup) continue;
                if (cpu_before < 0 || cpu_before != report.cpu || cpu_before != current_cpu()) {
                    ++report.cpu_migrations;
                    continue;
                }
                const unsigned pair = report.pairs;
                a[pair] = a_first ? first : second;
                b[pair] = a_first ? second : first;
                delta[pair] = a[pair] - b[pair];
                if (delta[pair] > 0) ++report.a_slower;
                ++report.pairs;
            }
            // Keep block order: overall medians are not the difference of A and B medians.
            for (unsigned offset = 0; offset + kBlockPairs <= report.pairs; offset += kBlockPairs) {
                std::array<int64_t, kBlockPairs> block{};
                for (unsigned j = 0; j < kBlockPairs; ++j) block[j] = delta[offset + j];
                sort(block, kBlockPairs);
                // Use the lower-middle sorted sample for even-sized blocks.
                const int64_t median = block[(kBlockPairs - 1) / 2];
                if (median > 0) ++report.positive_blocks;
                else if (median < 0) ++report.negative_blocks;
                else ++report.zero_blocks;
            }
            // Always calculate diagnostics from accepted pairs, including partial runs.
            if (report.pairs) {
                sort(a, report.pairs);
                sort(b, report.pairs);
                sort(delta, report.pairs);
                const unsigned middle = (report.pairs - 1) / 2;
                report.median_a_ns = a[middle];
                report.median_b_ns = b[middle];
                report.median_delta_ns = delta[middle];
                report.timing_medians_available = true;
            }
            if (const int error = verify_pinned(report.cpu)) {
                report.state = State::kInconclusive;
                report.error = error;
                return false;
            }
            if (report.pairs != kPairs || report.cpu_migrations) {
                // A migrated sample must never become a detection.
                report.state = State::kInconclusive;
                report.error = EAGAIN;
                return false;
            }
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
            // Timing is complete. Publish a counting-stage checkpoint before any check can fail,
            // so a later affinity change retains a decodable TIMING_ONLY sample.
            session.advance(Step::kAffinity);
            if (const int error = verify_pinned(report.cpu)) return session.stats_failed(error);
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
            report.pid = getpid();
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
                session.advance(Step::kAffinity);
                if (const int error = pin_to_allowed_cpu(report.cpu)) {
                    report.error = error;
                    report.state = State::kUnavailable;
                } else if (const int error = verify_pinned(report.cpu)) {
                    report.error = error;
                    report.state = State::kInconclusive;
                } else {
                    session.advance(Step::kTiming);
                    if (time_pairs(session)) {
                        report.state = State::kTimingOnly;
                        if (count_rounds(session)) report.state = State::kCollected;
                    }
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

    int verify_parent_timing_preflight() {
        std::array<unsigned char, sizeof(int)> record{};
        const auto child = common::run_disposable_child(record, kDeadlines,
                                                        [](int fd) { return parent_preflight_child(fd); });
        if (child.end != common::ChildEnd::kExited ||
            child.report_length != sizeof(int) || child.error != 0) return EPROTO;
        int error = EPROTO;
        std::memcpy(&error, record.data(), sizeof(error));
        if (child.exit_status != 0 && !error) return EPROTO;
        return error;
    }

}
