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

#ifndef DUCKDETECTOR_NATIVEROOT_COMMON_TYPES_H
#define DUCKDETECTOR_NATIVEROOT_COMMON_TYPES_H

#include <string>
#include <vector>

namespace duckdetector::nativeroot {

    enum class Severity {
        kDanger,
        kWarning,
        kInfo,
    };

    struct DetectionFlags {
        bool kernel_su = false;
        bool apatch = false;
        bool magisk = false;
        bool susfs = false;
    };

    struct Finding {
        std::string group;
        std::string label;
        std::string value;
        std::string detail;
        Severity severity = Severity::kWarning;
    };

    struct ProbeResult {
        DetectionFlags flags;
        int hit_count = 0;
        int checked_count = 0;
        int denied_count = 0;
        long numeric_value = 0;
        long extra_numeric_value = 0;
        long aux_flags = 0;
        std::string extra_text;
        std::vector<Finding> findings;
    };

    struct Snapshot {
        bool available = false;
        DetectionFlags flags;
        long kernel_su_version = 0;
        bool prctl_probe_hit = false;
        bool ksu_supercall_attempted = false;
        bool ksu_supercall_probe_hit = false;
        bool ksu_supercall_blocked = false;
        bool ksu_supercall_safe_mode = false;
        bool ksu_supercall_lkm = false;
        bool ksu_supercall_late_load = false;
        bool ksu_supercall_pr_build = false;
        bool ksu_supercall_manager = false;
        bool susfs_probe_hit = false;
        bool self_su_domain = false;
        std::string self_context;
        int self_ksu_driver_fd_count = 0;
        int self_ksu_fdwrapper_count = 0;
        int path_hit_count = 0;
        int path_check_count = 0;
        int process_hit_count = 0;
        int process_checked_count = 0;
        int process_denied_count = 0;
        int kernel_hit_count = 0;
        int kernel_source_count = 0;
        int property_hit_count = 0;
        int property_check_count = 0;
        std::vector<Finding> findings;
    };

    const char *to_string(Severity severity);

    void merge_flags(DetectionFlags &target, const DetectionFlags &source);

}  // namespace duckdetector::nativeroot

#endif  // DUCKDETECTOR_NATIVEROOT_COMMON_TYPES_H
