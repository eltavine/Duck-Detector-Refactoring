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

#include "nativeroot/probes/path_probe.h"

#include <string>

#include "nativeroot/common/io_utils.h"

namespace duckdetector::nativeroot {
    namespace {

        enum class SuspiciousPathCategory {
            kRootManager,
            kShellTmpArtifact,
            kSystemArtifact,
            kExternalArtifact,
        };

        struct PathRule {
            const char *path;
            const char *label;
            SuspiciousPathCategory category;
            bool kernel_su;
            bool apatch;
            bool magisk;
            Severity severity;
        };

        constexpr PathRule kPathRules[] = {
                {"/data/adb/ksud", "KernelSU daemon", SuspiciousPathCategory::kRootManager, true, false, false, Severity::kDanger},
                {"/data/adb/ksu", "KernelSU directory", SuspiciousPathCategory::kRootManager, true, false, false, Severity::kDanger},
                {"/data/adb/ksu/bin", "KernelSU binaries", SuspiciousPathCategory::kRootManager, true, false, false, Severity::kDanger},
                {"/data/adb/ksu/modules", "KernelSU modules", SuspiciousPathCategory::kRootManager, true, false, false, Severity::kDanger},
                {"/data/adb/apd", "APatch daemon", SuspiciousPathCategory::kRootManager, false, true, false, Severity::kDanger},
                {"/data/adb/ap", "APatch directory", SuspiciousPathCategory::kRootManager, false, true, false, Severity::kDanger},
                {"/data/adb/ap/bin", "APatch binaries", SuspiciousPathCategory::kRootManager, false, true, false, Severity::kDanger},
                {"/data/adb/ap/modules", "APatch modules", SuspiciousPathCategory::kRootManager, false, true, false, Severity::kDanger},
                {"/data/adb/apatch", "APatch residue", SuspiciousPathCategory::kRootManager, false, true, false, Severity::kDanger},
                {"/data/adb/magisk", "Magisk directory", SuspiciousPathCategory::kRootManager, false, false, true, Severity::kDanger},
                {"/data/adb/magisk/magiskd", "Magisk daemon", SuspiciousPathCategory::kRootManager, false, false, true, Severity::kDanger},
                {"/sbin/.magisk", "Magisk hidden dir", SuspiciousPathCategory::kRootManager, false, false, true, Severity::kDanger},
                {"/data/local/stryker", "Stryker residue", SuspiciousPathCategory::kSystemArtifact, false, false, false, Severity::kWarning},
                {"/data/system/AppRetention", "AppRetention residue", SuspiciousPathCategory::kSystemArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/luckys", "Luckys tmp residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/input_devices", "Input devices tmp residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/HyperCeiler", "HyperCeiler tmp residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/simpleHook", "simpleHook tmp residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/DisabledAllGoogleServices", "DisabledAllGoogleServices residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/MIO", "MIO residue", SuspiciousPathCategory::kSystemArtifact, false, false, false, Severity::kWarning},
                {"/data/DNA", "DNA residue", SuspiciousPathCategory::kSystemArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/cleaner_starter", "Cleaner starter residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/byyang", "Byyang tmp residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/mount_mask", "Mount mask residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/mount_mark", "Mount mark residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/scriptTMP", "Script tmp residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/local/luckys", "Luckys residue", SuspiciousPathCategory::kSystemArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/horae_control.log", "Horae control residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
                {"/data/gpu_freq_table.conf", "GPU freq table residue", SuspiciousPathCategory::kSystemArtifact, false, false, false, Severity::kWarning},
                {"/storage/emulated/0/Download/advanced", "Advanced download residue", SuspiciousPathCategory::kExternalArtifact, false, false, false, Severity::kWarning},
                {"/storage/emulated/0/Documents/advanced", "Advanced documents residue", SuspiciousPathCategory::kExternalArtifact, false, false, false, Severity::kWarning},
                {"/data/system/NoActive", "NoActive residue", SuspiciousPathCategory::kSystemArtifact, false, false, false, Severity::kWarning},
                {"/data/system/Freezer", "Freezer residue", SuspiciousPathCategory::kSystemArtifact, false, false, false, Severity::kWarning},
                {"/storage/emulated/0/Android/naki", "Naki external residue", SuspiciousPathCategory::kExternalArtifact, false, false, false, Severity::kWarning},
                {"/data/swap_config.conf", "Swap config residue", SuspiciousPathCategory::kSystemArtifact, false, false, false, Severity::kWarning},
                {"/data/local/tmp/resetprop", "resetprop tmp residue", SuspiciousPathCategory::kShellTmpArtifact, false, false, false, Severity::kWarning},
        };

        struct PathEvidence {
            bool stat_visible = false;
            bool lstat_visible = false;
            bool open_visible = false;
            bool parent_list_visible = false;

            bool metadata_visible() const {
                return stat_visible || lstat_visible;
            }

            int confirmation_count() const {
                return (metadata_visible() ? 1 : 0) +
                       (open_visible ? 1 : 0) +
                       (parent_list_visible ? 1 : 0);
            }
        };

        const char *category_label(const SuspiciousPathCategory category) {
            switch (category) {
                case SuspiciousPathCategory::kRootManager:
                    return "Root manager";
                case SuspiciousPathCategory::kShellTmpArtifact:
                    return "Shell tmp artifact";
                case SuspiciousPathCategory::kSystemArtifact:
                    return "System artifact";
                case SuspiciousPathCategory::kExternalArtifact:
                    return "External staging artifact";
            }
            return "Residue";
        }

        std::string parent_path_of(const char *path) {
            const std::string value(path == nullptr ? "" : path);
            const size_t separator = value.find_last_of('/');
            if (separator == std::string::npos) {
                return "";
            }
            if (separator == 0) {
                return "/";
            }
            return value.substr(0, separator);
        }

        std::string base_name_of(const char *path) {
            const std::string value(path == nullptr ? "" : path);
            const size_t separator = value.find_last_of('/');
            if (separator == std::string::npos) {
                return value;
            }
            if (separator + 1 >= value.size()) {
                return "";
            }
            return value.substr(separator + 1);
        }

        PathEvidence collect_path_evidence(const char *path) {
            PathEvidence evidence{
                    .stat_visible = file_exists(path),
                    .lstat_visible = path_exists_no_follow(path),
                    .open_visible = path_openable(path),
            };

            const std::string parent = parent_path_of(path);
            const std::string name = base_name_of(path);
            if (!parent.empty() && !name.empty()) {
                evidence.parent_list_visible =
                        directory_contains_entry(parent.c_str(), name.c_str());
            }
            return evidence;
        }

        std::string evidence_summary(const PathEvidence &evidence) {
            std::string summary;
            if (evidence.stat_visible) {
                summary += summary.empty() ? "stat" : ", stat";
            }
            if (evidence.lstat_visible) {
                summary += summary.empty() ? "lstat" : ", lstat";
            }
            if (evidence.open_visible) {
                summary += summary.empty() ? "openat" : ", openat";
            }
            if (evidence.parent_list_visible) {
                summary += summary.empty() ? "parent-getdents64" : ", parent-getdents64";
            }
            return summary.empty() ? "none" : summary;
        }

    }  // namespace

    ProbeResult run_path_probe() {
        ProbeResult result;
        result.checked_count = static_cast<int>(sizeof(kPathRules) / sizeof(kPathRules[0]));

        for (const PathRule &rule: kPathRules) {
            const PathEvidence evidence = collect_path_evidence(rule.path);
            if (evidence.confirmation_count() < 2) {
                continue;
            }
            result.flags.kernel_su = result.flags.kernel_su || rule.kernel_su;
            result.flags.apatch = result.flags.apatch || rule.apatch;
            result.flags.magisk = result.flags.magisk || rule.magisk;
            result.hit_count += 1;
            result.findings.push_back(
                    Finding{
                            .group = "PATH",
                            .label = rule.label,
                            .value = "Present",
                            .detail = std::string("Category: ") + category_label(rule.category) +
                                      "\nConfirmations: " +
                                      std::to_string(evidence.confirmation_count()) + "/3" +
                                      "\nEvidence: " + evidence_summary(evidence) +
                                      "\n" + rule.path,
                            .severity = rule.severity,
                    }
            );
        }

        return result;
    }

}  // namespace duckdetector::nativeroot
