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

#include "nativeroot/probes/susfs_opath_consistency_probe.h"

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif

namespace duckdetector::nativeroot {
    namespace {

        // susfs exposes optional /proc control nodes. On a clean kernel every
        // one of these paths is ENOENT on every interface. The susfs4ksu-lkm
        // port intercepts at the LSM layer and answers queries inconsistently:
        // open(O_PATH) succeeds while fstat on the returned fd reports ENOENT,
        // or stat() succeeds while open() fails. Any disagreement between the
        // stat/open/fstat interfaces is impossible for a genuine proc entry.
        const char *const kSusfsNodes[] = {
                "susfs_path", "susfs_kstat", "susfs_map", "susfs_uname",
                "susfs_avc_spoof", "susfs_enable_log", "susfs_hide_modules",
                "susfs_hide_mounts", "susfs_opath", "susfs_open_redirect",
                "susfs_spoof_cmdline", "susfs_variants",
        };

        void append_joined(std::string &target, const std::vector<std::string> &parts) {
            for (size_t i = 0; i < parts.size(); ++i) {
                if (i > 0) {
                    target += ", ";
                }
                target += parts[i];
            }
        }

    }  // namespace

    ProbeResult run_susfs_opath_consistency_probe() {
        ProbeResult result;
        result.numeric_value = static_cast<long>(SusfsOpathOutcome::kNotObserved);

        std::vector<std::string> degraded_lkm_nodes;
        std::vector<std::string> stat_open_mismatch_nodes;
        std::vector<std::string> visible_nodes;
        int checked = 0;

        for (const char *const node: kSusfsNodes) {
            const std::string path = std::string("/proc/") + node;

            struct stat path_stat{};
            const bool stat_ok = stat(path.c_str(), &path_stat) == 0;
            const int fd = open(path.c_str(), O_PATH | O_CLOEXEC);
            const int open_errno = errno;
            ++checked;

            if (stat_ok && fd < 0) {
                stat_open_mismatch_nodes.push_back(node);
                continue;
            }
            if (fd < 0) {
                continue;
            }

            struct stat fd_stat{};
            if (fstat(fd, &fd_stat) == 0) {
                visible_nodes.push_back(node);
            } else if (errno == ENOENT) {
                // open() resolved the node but fstat() on the same fd says it
                // does not exist: impossible for a real proc entry, and the
                // signature of the lkm port's LSM-level interception.
                degraded_lkm_nodes.push_back(node);
            } else {
                stat_open_mismatch_nodes.push_back(node);
            }
            close(fd);
        }

        const bool any_inconsistency = !degraded_lkm_nodes.empty() ||
                                       !stat_open_mismatch_nodes.empty() ||
                                       !visible_nodes.empty();
        result.checked_count = checked;
        result.numeric_value = static_cast<long>(any_inconsistency
                                                          ? SusfsOpathOutcome::kInconsistent
                                                          : SusfsOpathOutcome::kConsistent);

        std::string detail = std::to_string(checked) + " /proc/susfs_* nodes checked. ";
        if (!any_inconsistency) {
            detail += "All interfaces returned ENOENT for every node.";
            result.extra_text = detail;
            return result;
        }

        if (!degraded_lkm_nodes.empty()) {
            detail += "open(O_PATH) succeeded but fstat returned ENOENT on: ";
            append_joined(detail, degraded_lkm_nodes);
            detail += ". ";
            result.findings.push_back(
                    Finding{
                            .group = "SIDE_CHANNEL",
                            .label = "susfs LKM O_PATH inconsistency",
                            .value = std::to_string(degraded_lkm_nodes.size()) + " nodes",
                            .detail = "open(O_PATH) resolves /proc/susfs_* but fstat on the returned fd reports ENOENT - impossible for a genuine proc entry and the signature of the susfs4ksu-lkm LSM-level interception.",
                            .severity = Severity::kDanger,
                    }
            );
        }
        if (!stat_open_mismatch_nodes.empty()) {
            detail += "stat() and open() disagree on: ";
            append_joined(detail, stat_open_mismatch_nodes);
            detail += ". ";
            result.findings.push_back(
                    Finding{
                            .group = "SIDE_CHANNEL",
                            .label = "susfs proc node interface mismatch",
                            .value = std::to_string(stat_open_mismatch_nodes.size()) + " nodes",
                            .detail = "stat() and open() disagree on /proc/susfs_* nodes - interfaces cannot disagree for a genuine proc entry.",
                            .severity = Severity::kWarning,
                    }
            );
        }
        if (!visible_nodes.empty()) {
            detail += "Visible nodes: ";
            append_joined(detail, visible_nodes);
            detail += ".";
            result.findings.push_back(
                    Finding{
                            .group = "SIDE_CHANNEL",
                            .label = "susfs proc nodes visible",
                            .value = std::to_string(visible_nodes.size()) + " nodes",
                            .detail = "susfs control nodes are exposed under /proc, which indicates a susfs build (any flavor) on this kernel.",
                            .severity = Severity::kWarning,
                    }
            );
        }

        result.flags.susfs = true;
        result.hit_count = static_cast<int>(degraded_lkm_nodes.size() +
                                            stat_open_mismatch_nodes.size() +
                                            visible_nodes.size());
        result.extra_text = detail;
        return result;
    }

}  // namespace duckdetector::nativeroot
