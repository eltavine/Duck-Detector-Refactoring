// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/proc_attr_probe.h"
#include <cerrno>
#include <cstring>
#include <unistd.h>

namespace duckdetector::selinux::proc_attr {
    namespace {
        constexpr common::ChildDeadlines kDeadlines{std::chrono::milliseconds(1000), std::chrono::milliseconds(250)};
        bool denied(const WriteResult &result, const int error) {
            return result.open_error == 0 && result.bytes == -1 && result.write_error == error;
        }
        bool send_report(const int fd, const Report &report) {
            const auto *data = reinterpret_cast<const unsigned char *>(&report);
            size_t sent = 0;
            while (sent < sizeof(report)) {
                const ssize_t count = write(fd, data + sent, sizeof(report) - sent);
                if (count < 0 && errno == EINTR) continue;
                if (count <= 0) return false;
                sent += static_cast<size_t>(count);
            }
            return true;
        }
        bool identity(Report &report, const uid_t uid) {
            char context[128]{};
            report.error = read_identity(context, sizeof(context));
            if (report.error) { report.state = State::kUnavailable; return false; }
            if (getuid() != uid || std::strcmp(context, kCarrier)) {
                report.identity_changed = true;
                report.state = State::kInconclusive;
                return false;
            }
            return true;
        }
        bool control(Report &report, Controls &controls, const uid_t uid, const int fd) {
            controls.malformed = write_current(kMalformed);
            if (!send_report(fd, report)) return false;
            if (!denied(controls.malformed, EINVAL)) {
                report.error = controls.malformed.open_error ?: controls.malformed.write_error;
                report.state = report.error == EACCES || report.error == EPERM
                               ? State::kPermissionLimited : State::kInconclusive;
                return false;
            }
            // ACK converts this known stock label before denying app_zygote -> app_zygote dyntransition.
            // The malformed control proves conversion is reached; an open denial is never equivalent.
            controls.stock = write_current(kCarrier);
            if (!send_report(fd, report)) return false;
            if (!denied(controls.stock, EACCES)) {
                report.error = controls.stock.open_error ?: controls.stock.write_error;
                report.state = State::kInconclusive;
                return false;
            }
            return identity(report, uid);
        }
        int run_child(const int fd) {
            Report report;
            const uid_t uid = getuid();
            char context[128]{};
            report.error = read_identity(context, sizeof(context));
            if (report.error || uid < 10000 || std::strcmp(context, kCarrier)) {
                report.state = report.error ? State::kUnavailable : State::kUnsupported;
                return send_report(fd, report) ? 0 : 1;
            }
            for (unsigned round = 0; round < kRounds; ++round) {
                report.step = Step::kControlsBefore;
                if (!send_report(fd, report)) return 1;
                if (!control(report, report.controls[round * 2], uid, fd)) break;
                report.step = Step::kTargets;
                if (!send_report(fd, report)) return 1;
                bool stopped = false;
                for (unsigned index = 0; index < kTargets; ++index) {
                    auto &result = report.writes[round][index];
                    result = write_current(targets[index].context);
                    // Any successful or short write stops the whole experiment in this disposable child.
                    // Even a success without a visible identity change invalidates the refusal model.
                    if (result.bytes >= 0 || !identity(report, uid)) {
                        report.state = State::kInconclusive;
                        stopped = true;
                    }
                    if (!send_report(fd, report)) return 1;
                    if (stopped) break;
                }
                if (stopped) break;
                report.step = Step::kControlsAfter;
                if (!control(report, report.controls[round * 2 + 1], uid, fd)) break;
                ++report.completed_rounds;
                if (!send_report(fd, report)) return 1;
            }
            if (report.completed_rounds == kRounds) {
                report.state = State::kComplete;
                report.step = Step::kFinished;
            }
            return send_report(fd, report) ? 0 : 1;
        }
    }
    Result collect() {
        Result result;
        // At most 33 progress records, including the final state. Retain completed IO on faults.
        std::array<unsigned char, sizeof(Report) * 40> bytes{};
        result.child = common::run_disposable_child(bytes, kDeadlines, [](int fd) { return run_child(fd); });
        if (result.child.report_length >= sizeof(Report)) {
            const auto offset = (result.child.report_length / sizeof(Report) - 1) * sizeof(Report);
            std::memcpy(&result.report, bytes.data() + offset, sizeof(Report));
        }
        if (result.child.end != common::ChildEnd::kExited || result.child.exit_status != 0 ||
            result.child.report_length < sizeof(Report) || result.child.report_length % sizeof(Report)) {
            result.report.state = result.child.end == common::ChildEnd::kNotStarted ||
                                  result.child.end == common::ChildEnd::kSetupFailed
                                  ? State::kUnavailable : State::kInconclusive;
            if (result.child.error) result.report.error = result.child.error;
        }
        return result;
    }
}
