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

#include "nativeroot/snapshot_builder.h"

#include <set>
#include <string>

#include "nativeroot/common/codec.h"
#include "nativeroot/probes/kernel_probe.h"
#include "nativeroot/probes/ksu_supercall_probe.h"
#include "nativeroot/probes/path_probe.h"
#include "nativeroot/probes/process_probe.h"
#include "nativeroot/probes/property_probe.h"
#include "nativeroot/probes/prctl_probe.h"
#include "nativeroot/probes/self_process_ioc_probe.h"
#include "nativeroot/probes/susfs_probe.h"

namespace duckdetector::nativeroot {
    namespace {

        void append_probe_findings(
                Snapshot &snapshot,
                const ProbeResult &probe,
                std::set<std::string> &dedupe
        ) {
            merge_flags(snapshot.flags, probe.flags);
            for (const Finding &finding: probe.findings) {
                const std::string key = finding.group + "|" + finding.label + "|" + finding.detail;
                if (!dedupe.insert(key).second) {
                    continue;
                }
                snapshot.findings.push_back(finding);
            }
        }

    }  // namespace

    Snapshot collect_snapshot(const bool skip_ksu_supercall) {
        Snapshot snapshot;
        snapshot.available = true;

        const ProbeResult prctl_probe = run_prctl_probe();
        const ProbeResult susfs_probe = run_susfs_probe();
        const ProbeResult self_process_ioc_probe = run_self_process_ioc_probe();
        // Xiaomi-family devices are known to hard-crash on the sacrificial reboot syscall path.
        const ProbeResult ksu_supercall_probe =
                skip_ksu_supercall ? ProbeResult{} : run_ksu_supercall_probe();
        const ProbeResult path_probe = run_path_probe();
        const ProbeResult process_probe = run_process_probe();
        const ProbeResult kernel_probe = run_kernel_probe();
        const ProbeResult property_probe = run_property_probe();

        snapshot.kernel_su_version = prctl_probe.numeric_value > 0
                                     ? prctl_probe.numeric_value
                                     : ksu_supercall_probe.numeric_value;
        snapshot.prctl_probe_hit = prctl_probe.flags.kernel_su;
        snapshot.ksu_supercall_attempted = ksu_supercall_probe.checked_count > 0;
        snapshot.ksu_supercall_probe_hit = ksu_supercall_probe.flags.kernel_su;
        snapshot.ksu_supercall_blocked = ksu_supercall_probe.denied_count > 0;
        snapshot.ksu_supercall_safe_mode = ksu_supercall_probe.aux_flags != 0;
        snapshot.ksu_supercall_lkm =
                (ksu_supercall_probe.extra_numeric_value & (1U << 0)) != 0;
        snapshot.ksu_supercall_manager =
                (ksu_supercall_probe.extra_numeric_value & (1U << 1)) != 0;
        snapshot.ksu_supercall_late_load =
                (ksu_supercall_probe.extra_numeric_value & (1U << 2)) != 0;
        snapshot.ksu_supercall_pr_build =
                (ksu_supercall_probe.extra_numeric_value & (1U << 3)) != 0;
        snapshot.susfs_probe_hit = susfs_probe.flags.susfs;
        snapshot.self_context = self_process_ioc_probe.extra_text;
        snapshot.self_su_domain = self_process_ioc_probe.aux_flags != 0;
        snapshot.self_ksu_driver_fd_count = static_cast<int>(self_process_ioc_probe.numeric_value);
        snapshot.self_ksu_fdwrapper_count = static_cast<int>(
                self_process_ioc_probe.extra_numeric_value
        );
        snapshot.path_hit_count = path_probe.hit_count;
        snapshot.path_check_count = path_probe.checked_count;
        snapshot.process_hit_count = process_probe.hit_count;
        snapshot.process_checked_count = process_probe.checked_count;
        snapshot.process_denied_count = process_probe.denied_count;
        snapshot.kernel_hit_count = kernel_probe.hit_count;
        snapshot.kernel_source_count = kernel_probe.checked_count;
        snapshot.property_hit_count = property_probe.hit_count;
        snapshot.property_check_count = property_probe.checked_count;

        std::set<std::string> dedupe;
        append_probe_findings(snapshot, prctl_probe, dedupe);
        append_probe_findings(snapshot, susfs_probe, dedupe);
        append_probe_findings(snapshot, self_process_ioc_probe, dedupe);
        append_probe_findings(snapshot, ksu_supercall_probe, dedupe);
        append_probe_findings(snapshot, path_probe, dedupe);
        append_probe_findings(snapshot, process_probe, dedupe);
        append_probe_findings(snapshot, kernel_probe, dedupe);
        append_probe_findings(snapshot, property_probe, dedupe);

        return snapshot;
    }

}  // namespace duckdetector::nativeroot
