/*
 * Copyright 2026 Duck Apps Contributor
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

#include "selinux/context_validity_probe.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <utility>
#include <unistd.h>

namespace duckdetector::selinux {
    namespace {

        constexpr const char *kProcAttrCurrentPath = "/proc/self/attr/current";
        constexpr const char *kSelinuxContextPath = "/sys/fs/selinux/context";
        constexpr const char *kExpectedCarrierType = "app_zygote";
        constexpr const char *kKsuContext = "u:r:ksu:s0";
        constexpr const char *kKsuFileContext = "u:object_r:ksu_file:s0";
        constexpr const char *kNegativeControlContext = "u:r:duckdetector_context_oracle_sentinel:s0";
        constexpr const char *kStockFileControlContext = "u:object_r:system_data_file:s0";
        constexpr const char *kNegativeFileControlContext =
                "u:object_r:duckdetector_context_oracle_sentinel_file:s0";
        constexpr const char *kQueryMethod = "raw selinuxfs write";

        struct ContextCheckResult {
            std::optional<bool> valid;
            std::string note;
        };

        struct ControlPairResult {
            ContextCheckResult first;
            ContextCheckResult second;
            bool stable = false;
        };

        std::string trim(std::string value) {
            while (!value.empty() &&
                   (value.back() == '\n' || value.back() == '\r' || value.back() == '\0' ||
                    value.back() == ' ' || value.back() == '\t')) {
                value.pop_back();
            }
            while (!value.empty() &&
                   (value.front() == ' ' || value.front() == '\t')) {
                value.erase(value.begin());
            }
            return value;
        }

        std::string read_process_context() {
            std::ifstream input(kProcAttrCurrentPath);
            if (!input) {
                return {};
            }

            std::string context;
            std::getline(input, context, '\0');
            return trim(std::move(context));
        }

        std::string context_type(const std::string &context) {
            const std::size_t first = context.find(':');
            if (first == std::string::npos) {
                return {};
            }
            const std::size_t second = context.find(':', first + 1);
            if (second == std::string::npos) {
                return {};
            }
            const std::size_t third = context.find(':', second + 1);
            if (third == std::string::npos) {
                return context.substr(second + 1);
            }
            return context.substr(second + 1, third - second - 1);
        }

        void append_note(ContextValidityProbeSnapshot &snapshot, std::string note) {
            if (!note.empty()) {
                snapshot.notes.push_back(std::move(note));
            }
        }

        void append_boolean_note(
                ContextValidityProbeSnapshot &snapshot,
                const char *label,
                const std::optional<bool> &value
        ) {
            if (!value.has_value()) {
                append_note(snapshot, std::string(label) + "=unavailable");
                return;
            }
            append_note(snapshot, std::string(label) + (*value ? "=yes" : "=no"));
        }

        bool stable_result(
                const ContextCheckResult &first,
                const ContextCheckResult &second
        ) {
            return first.valid.has_value() == second.valid.has_value() &&
                   (!first.valid.has_value() || *first.valid == *second.valid);
        }

        ContextCheckResult check_context_validity(const char *context);

        bool pair_matches_expected(
                const ControlPairResult &pair,
                const bool expected_valid
        ) {
            return pair.stable &&
                   pair.first.valid.has_value() &&
                   *pair.first.valid == expected_valid;
        }

        std::optional<bool> pair_valid_value(const ControlPairResult &pair) {
            if (!pair_matches_expected(pair, true) && !pair_matches_expected(pair, false)) {
                return std::nullopt;
            }
            return pair.first.valid;
        }

        std::optional<bool> pair_rejected_value(const ControlPairResult &pair) {
            if (!pair.stable || !pair.first.valid.has_value()) {
                return std::nullopt;
            }
            return !*pair.first.valid;
        }

        ControlPairResult check_context_pair_validity(const char *context) {
            ControlPairResult result;
            result.first = check_context_validity(context);
            result.second = check_context_validity(context);
            result.stable = stable_result(result.first, result.second);
            return result;
        }

        void append_repeat_note(
                ContextValidityProbeSnapshot &snapshot,
                const char *label,
                const ContextCheckResult &result
        ) {
            std::string line(label);
            line += '=';
            if (result.valid.has_value()) {
                line += *result.valid ? "valid" : "invalid";
            } else {
                line += "unavailable";
            }
            if (!result.note.empty()) {
                line += " (";
                line += result.note;
                line += ')';
            }
            append_note(snapshot, std::move(line));
        }

        ContextCheckResult check_context_validity(const char *context) {
            ContextCheckResult result;

            int fd = open(kSelinuxContextPath, O_RDWR | O_CLOEXEC);
            if (fd < 0) {
                const int error = errno;
                if (error == EINVAL) {
                    result.valid = false;
                    result.note = std::string("Invalid context: ") + context +
                                  " errno=" + std::to_string(error);
                } else {
                    result.note = std::string("Unavailable: ") + context +
                                  " errno=" + std::to_string(error);
                }
                return result;
            }

            const ssize_t written = write(fd, context, std::strlen(context) + 1);
            const int error = errno;
            close(fd);

            if (written >= 0) {
                result.valid = true;
                return result;
            }

            if (error == EINVAL) {
                result.valid = false;
                result.note = std::string("Invalid context: ") + context +
                              " errno=" + std::to_string(error);
            } else {
                result.note = std::string("Unavailable: ") + context +
                              " errno=" + std::to_string(error);
            }
            return result;
        }

    }  // namespace

    ContextValidityProbeSnapshot collect_context_validity_snapshot() {
        ContextValidityProbeSnapshot snapshot;
        snapshot.query_method = kQueryMethod;

        const std::string carrier_context = read_process_context();
        if (carrier_context.empty()) {
            snapshot.failure_reason = "Current process SELinux context unreadable.";
            return snapshot;
        }

        snapshot.available = true;
        snapshot.carrier_context = carrier_context;
        snapshot.carrier_matches_expected = context_type(carrier_context) == kExpectedCarrierType;
        append_note(snapshot, std::string("Carrier context: ") + carrier_context);
        append_note(snapshot, std::string("Expected carrier type: ") + kExpectedCarrierType);

        if (!snapshot.carrier_matches_expected) {
            snapshot.failure_reason = "Carrier context is not app_zygote.";
            append_note(snapshot, "The oracle is only meaningful from an app_zygote carrier.");
            return snapshot;
        }

        snapshot.probe_attempted = true;

        const ControlPairResult carrier_control = check_context_pair_validity(carrier_context.c_str());
        const ControlPairResult negative_control = check_context_pair_validity(kNegativeControlContext);
        const ControlPairResult file_control = check_context_pair_validity(kStockFileControlContext);
        const ControlPairResult negative_file_control =
                check_context_pair_validity(kNegativeFileControlContext);

        snapshot.carrier_control_valid = pair_valid_value(carrier_control);
        snapshot.negative_control_rejected = pair_rejected_value(negative_control);
        snapshot.file_control_valid = pair_valid_value(file_control);
        snapshot.file_negative_control_rejected = pair_rejected_value(negative_file_control);
        snapshot.oracle_controls_passed =
                pair_matches_expected(carrier_control, true) &&
                pair_matches_expected(negative_control, false) &&
                pair_matches_expected(file_control, true) &&
                pair_matches_expected(negative_file_control, false);

        append_note(snapshot, std::string("Query method: ") + kQueryMethod);
        append_note(snapshot, std::string("Positive control context: ") + carrier_context);
        append_note(snapshot, std::string("Negative control context: ") + kNegativeControlContext);
        append_note(snapshot, std::string("File control context: ") + kStockFileControlContext);
        append_note(snapshot,
                    std::string("File negative control context: ") + kNegativeFileControlContext);
        append_note(snapshot, carrier_control.first.note);
        append_note(snapshot, negative_control.first.note);
        append_note(snapshot, file_control.first.note);
        append_note(snapshot, negative_file_control.first.note);
        if (!carrier_control.stable) {
            append_note(snapshot, "Carrier control repeated inconsistently.");
        }
        if (!negative_control.stable) {
            append_note(snapshot, "Negative control repeated inconsistently.");
        }
        if (!file_control.stable) {
            append_note(snapshot, "File control repeated inconsistently.");
        }
        if (!negative_file_control.stable) {
            append_note(snapshot, "File negative control repeated inconsistently.");
        }
        append_boolean_note(snapshot, "Carrier control valid", snapshot.carrier_control_valid);
        append_boolean_note(snapshot, "Negative control rejected", snapshot.negative_control_rejected);
        append_boolean_note(snapshot, "File control valid", snapshot.file_control_valid);
        append_boolean_note(snapshot,
                            "File negative control rejected",
                            snapshot.file_negative_control_rejected);

        if (!snapshot.oracle_controls_passed) {
            snapshot.failure_reason = "Context validity oracle self-test failed.";
            append_note(snapshot,
                        "KSU-specific context queries were skipped to avoid interpreting an untrusted oracle.");
            return snapshot;
        }

        const ContextCheckResult domain_first = check_context_validity(kKsuContext);
        const ContextCheckResult domain_second = check_context_validity(kKsuContext);
        const ContextCheckResult file_first = check_context_validity(kKsuFileContext);
        const ContextCheckResult file_second = check_context_validity(kKsuFileContext);

        const bool domain_stable = stable_result(domain_first, domain_second);
        const bool file_stable = stable_result(file_first, file_second);
        snapshot.ksu_results_stable = domain_stable && file_stable;

        append_repeat_note(snapshot, "Domain repeat 1", domain_first);
        append_repeat_note(snapshot, "Domain repeat 2", domain_second);
        append_repeat_note(snapshot, "File repeat 1", file_first);
        append_repeat_note(snapshot, "File repeat 2", file_second);

        if (!snapshot.ksu_results_stable) {
            snapshot.failure_reason = "Context validity oracle repeatability failed.";
            append_note(snapshot,
                        "The KSU-specific context verdict changed across repeated writes, so it was not trusted.");
            return snapshot;
        }

        const ContextCheckResult domain_result = domain_first;
        const ContextCheckResult file_result = file_first;

        snapshot.ksu_domain_valid = domain_result.valid;
        snapshot.ksu_file_valid = file_result.valid;
        append_note(snapshot, domain_result.note);
        append_note(snapshot, file_result.note);

        if (domain_result.valid.has_value() && file_result.valid.has_value()) {
            snapshot.bit_pair.push_back(*domain_result.valid ? '1' : '0');
            snapshot.bit_pair.push_back(*file_result.valid ? '1' : '0');
            if (*domain_result.valid && *file_result.valid) {
                append_note(snapshot, "Both KSU-specific contexts were accepted by live policy.");
            } else if (!*domain_result.valid && !*file_result.valid) {
                append_note(snapshot, "Neither KSU-specific context was accepted by live policy.");
            } else {
                append_note(snapshot,
                            "Split verdict: one KSU-specific context was accepted while the other was not.");
            }
            return snapshot;
        }

        snapshot.failure_reason = "Context validity probe could not complete both checks.";
        if (!domain_result.valid.has_value() || !file_result.valid.has_value()) {
            append_note(snapshot,
                        "At least one KSU context write was unavailable from the current carrier.");
        }
        return snapshot;
    }

}  // namespace duckdetector::selinux
