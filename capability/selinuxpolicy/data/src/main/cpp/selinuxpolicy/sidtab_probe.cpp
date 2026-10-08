/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "selinuxpolicy/sidtab_probe.h"
#include "selinuxpolicy/sidtab_probe_io.h"
#include "common/disposable_child.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/random.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

namespace duckdetector::selinux::sidtab {
    namespace {
        constexpr char kCarrier[] = "u:r:app_zygote:s0";
        constexpr char kMalformed[] = "duckdetector-invalid-context";
        constexpr common::ChildDeadlines kDeadlines{std::chrono::milliseconds(1000), std::chrono::milliseconds(250)};

        State error_state(const int error) {
            if (error == EACCES || error == EPERM) return State::kPermissionLimited;
            // ENOENT is unavailable: a namespace or path filter may hide a supported interface.
            return error != 0 ? State::kUnavailable : State::kInconclusive;
        }

        bool send_report(const int fd, const Report &report) {
            const auto *bytes = reinterpret_cast<const unsigned char *>(&report);
            std::size_t offset = 0;
            while (offset < sizeof(report)) {
                const ssize_t count = write(fd, bytes + offset, sizeof(report) - offset);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) return false;
                offset += static_cast<std::size_t>(count);
            }
            return true;
        }

        bool require_io(Report &report, const IoResult result) {
            if (result.complete) return true;
            report.error = result.error;
            report.state = error_state(result.error);
            return false;
        }

        // invalid_state is what EINVAL means for this context: a policy that rejects the stock type + MLS
        // candidates does not support the experiment, while rejecting the carrier's own label contradicts
        // the process that is running under it.
        bool query(Report &report, const char *context, int &error, const State invalid_state) {
            bool canonical = false;
            const auto result = check_context(context, canonical);
            error = result.error;
            if (!result.complete && result.error == 0) report.canonical_mismatch = !canonical;
            if (!result.complete && result.error == EINVAL) {
                report.state = invalid_state;
                report.error = result.error;
                return false;
            }
            return require_io(report, result);
        }

        bool identity(Report &report) {
            char current[kContextBytes]{};
            if (!require_io(report, read_context(current, sizeof(current)))) return false;
            if (std::strcmp(current, report.carrier) == 0) return true;
            report.identity_changed = true;
            report.state = State::kInconclusive;
            return false;
        }

        bool run_round(Report &report, Round &round, const int fd) {
            report.step = Step::kControls;
            if (!require_io(report, read_entries(round.before_controls))) return false;
            if (!query(report, report.carrier, round.positive_error, State::kInconclusive)) return false;
            bool canonical = false;
            const auto negative = check_context(kMalformed, canonical);
            round.negative_error = negative.error;
            if (negative.complete || negative.error != EINVAL) {
                report.state = negative.error == EACCES || negative.error == EPERM
                               ? State::kPermissionLimited : State::kInconclusive;
                report.error = negative.error;
                return false;
            }
            // selinux_setprocattr checks setcurrent before it converts the label, and only conversion fails
            // a malformed label with EINVAL. Passing this control places a later EACCES after conversion:
            // a single-threaded child has only the dyntransition and ptrace checks left to fail.
            const auto attr_negative = write_current(kMalformed);
            round.attr_negative_error = attr_negative.error;
            if (!attr_negative.submitted) return require_io(report, attr_negative);
            if (attr_negative.complete || attr_negative.error != EINVAL) {
                report.state = attr_negative.error == EACCES ? State::kPermissionLimited : State::kInconclusive;
                report.error = attr_negative.error;
                return false;
            }
            if (!require_io(report, read_entries(round.before))) return false;
            if (!send_report(fd, report)) return false;

            report.step = Step::kContext;
            for (auto &sample : round.samples) {
                if (!query(report, sample.context, sample.context_error, State::kUnsupported)) return false;
            }
            if (!require_io(report, read_entries(round.after_context))) return false;
            if (!send_report(fd, report)) return false;

            report.step = Step::kAttrCurrent;
            for (auto &sample : round.samples) {
                // ACK hooks.c converts the context before dyntransition permission checks.
                // The KSU parent of a810677 calls the original handler for stock-valid contexts.
                const auto result = write_current(sample.context);
                sample.attr_error = result.error;
                if (!result.submitted) return require_io(report, result);
                // Not EPERM: proc_pid_attr_write returns it before the LSM hook runs, and the
                // bounded-transition EPERM applies only to multi-threaded callers.
                if (result.complete || result.error != EACCES) {
                    report.state = State::kInconclusive;
                    report.error = result.error;
                    // A permitted transition is never attempted in the carrier itself.
                    if (result.complete) report.identity_changed = true;
                    return false;
                }
                if (!identity(report)) return false;
            }
            if (!require_io(report, read_entries(round.after_attr))) return false;
            if (!send_report(fd, report)) return false;

            report.step = Step::kRepeat;
            for (auto &sample : round.samples) {
                if (!query(report, sample.context, sample.repeat_error, State::kUnsupported)) return false;
            }
            return require_io(report, read_entries(round.after_repeat)) &&
                   require_io(report, read_entries(round.idle_end)) && identity(report);
        }

        int run_child(const int fd, Report report) {
            report.step = Step::kCarrier;
            if (!require_io(report, read_context(report.carrier, sizeof(report.carrier)))) {
                send_report(fd, report);
                return 0;
            }
            // Do not assume UID alone means app_zygote. Its AOSP policy owns query/setcurrent access.
            if (getuid() < 10000 || std::strcmp(report.carrier, kCarrier) != 0) {
                report.state = State::kUnsupported;
                send_report(fd, report);
                return 0;
            }
            if (!send_report(fd, report)) return 0;
            for (auto &round : report.rounds) {
                if (!run_round(report, round, fd)) {
                    send_report(fd, report);
                    return 0;
                }
                ++report.completed_rounds;
                if (!send_report(fd, report)) return 0;
            }
            report.step = Step::kFinished;
            report.state = State::kComplete;
            send_report(fd, report);
            return 0;
        }

        bool prepare_contexts(Report &report) {
            constexpr std::size_t kEntropyBytes = kRounds * kSamples * 8;
            static_assert(kEntropyBytes <= 256, "getentropy accepts at most 256 bytes");
            std::array<unsigned char, kEntropyBytes> entropy{};
            // bionic's getentropy (API 28) falls back to /dev/urandom when getrandom fails.
            if (getentropy(entropy.data(), entropy.size()) != 0) {
                report.error = errno;
                return false;
            }
            unsigned cursor = 0;
            for (auto &round : report.rounds) {
                for (auto &sample : round.samples) {
                    std::size_t used = std::strlen(kCarrier);
                    std::memcpy(sample.context, kCarrier, used);
                    // Eight separated categories in c0..c1023; no adjacent categories to canonicalize
                    // into ranges. AOSP MLS permits subsets, but actual acceptance is verified.
                    for (unsigned category = 0; category < 8; ++category) {
                        const unsigned value = category * 128 + 1 + entropy[cursor++] % 126;
                        const int added = std::snprintf(sample.context + used, sizeof(sample.context) - used,
                                                        category == 0 ? ":c%u" : ",c%u", value);
                        if (added <= 0 || static_cast<std::size_t>(added) >= sizeof(sample.context) - used) return false;
                        used += static_cast<std::size_t>(added);
                    }
                }
            }
            return true;
        }

        // The record is copied out of another process; bound its strings before they are encoded.
        void terminate_strings(Report &report) {
            report.carrier[kContextBytes - 1] = 0;
            for (auto &round : report.rounds) {
                for (auto &sample : round.samples) sample.context[kContextBytes - 1] = 0;
            }
        }
    }

    Result collect() {
        Result result;
        result.uid = static_cast<int>(getuid());
        result.pid = static_cast<int>(getpid());
        timespec captured{};
        if (clock_gettime(CLOCK_BOOTTIME, &captured) == 0)
            result.captured_uptime_ms = captured.tv_sec * int64_t{1000} + captured.tv_nsec / 1'000'000;
        utsname kernel{};
        if (uname(&kernel) == 0) result.kernel_release = kernel.release;
        if (!prepare_contexts(result.report)) {
            // Candidate generation is local setup; its failure says nothing about the probed interfaces.
            result.report.state = State::kUnavailable;
            result.child_end = "NOT_STARTED";
            return result;
        }
        // Each progress record is fixed-size. The runner may receive several records or a partial
        // final record; only the last complete one is usable, and an unfinished child cannot pass.
        std::array<unsigned char, sizeof(Report) * 12> bytes{};
        const Report prepared = result.report;
        const auto child = common::run_disposable_child(bytes, kDeadlines, [&prepared](const int fd) {
            return run_child(fd, prepared);
        });
        result.attempted = child.end != common::ChildEnd::kNotStarted && child.end != common::ChildEnd::kSetupFailed;
        if (child.report_length >= sizeof(Report)) {
            const auto offset = (child.report_length / sizeof(Report) - 1) * sizeof(Report);
            std::memcpy(&result.report, bytes.data() + offset, sizeof(Report));
            terminate_strings(result.report);
        }
        result.signal = child.signal;
        switch (child.end) {
            case common::ChildEnd::kExited: result.child_end = "EXITED"; break;
            case common::ChildEnd::kNotStarted: result.child_end = "NOT_STARTED"; break;
            case common::ChildEnd::kSetupFailed: result.child_end = "SETUP_FAILED"; break;
            case common::ChildEnd::kSignaled: result.child_end = "SIGNALED"; break;
            case common::ChildEnd::kSeccompTrapped: result.child_end = "SECCOMP_TRAPPED"; break;
            case common::ChildEnd::kTimedOut: result.child_end = "TIMED_OUT"; break;
            case common::ChildEnd::kNotReaped: result.child_end = "NOT_REAPED"; break;
            case common::ChildEnd::kWaitFailed: result.child_end = "WAIT_FAILED"; break;
        }
        if (child.end != common::ChildEnd::kExited || child.exit_status != 0 || child.report_length < sizeof(Report)) {
            result.report.state = result.attempted ? State::kInconclusive : State::kUnavailable;
            if (child.error) result.report.error = child.error;
        }
        return result;
    }
} // namespace duckdetector::selinux::sidtab
