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

#ifndef DUCKDETECTOR_SELINUX_CONTEXT_VALIDITY_PROBE_H
#define DUCKDETECTOR_SELINUX_CONTEXT_VALIDITY_PROBE_H

#include <jni.h>
#include <optional>
#include <string>
#include <vector>

namespace duckdetector::selinux {

    struct DirtyPolicyProbeSnapshot {
        bool available = false;
        bool probe_attempted = false;
        std::string carrier_context;
        bool carrier_matches_expected = false;
        std::optional<bool> access_control_allowed;
        std::optional<bool> negative_control_rejected;
        std::optional<bool> system_server_execmem_allowed;
        std::optional<bool> fsck_sys_admin_allowed;
        std::optional<bool> shell_su_transition_allowed;
        std::optional<bool> adbd_adbroot_binder_call_allowed;
        std::optional<bool> magisk_binder_call_allowed;
        std::optional<bool> ksu_file_read_allowed;
        std::optional<bool> lsposed_file_read_allowed;
        std::optional<bool> xposed_data_file_read_allowed;
        std::optional<bool> zygote_adb_data_search_allowed;
        bool controls_passed = false;
        bool stable = false;
        std::string query_method;
        std::string failure_reason;
        std::vector<std::string> notes;
    };

    struct ContextValidityProbeSnapshot {
        bool available = false;
        bool probe_attempted = false;
        std::string carrier_context;
        bool carrier_matches_expected = false;
        std::optional<bool> selinux_enabled;
        std::optional<bool> selinux_enforced;
        std::optional<bool> pid_context_matches_current;
        std::optional<bool> proc_self_context_matches_current;
        std::optional<bool> dyntransition_check_passed;
        std::optional<bool> carrier_control_valid;
        std::optional<bool> negative_control_rejected;
        std::optional<bool> file_control_valid;
        std::optional<bool> file_negative_control_rejected;
        bool oracle_controls_passed = false;
        bool ksu_results_stable = false;
        std::string query_method;
        std::optional<bool> ksu_domain_valid;
        std::optional<bool> ksu_file_valid;
        std::string bit_pair;
        DirtyPolicyProbeSnapshot dirty_policy;
        std::string failure_reason;
        std::vector<std::string> notes;
    };

    ContextValidityProbeSnapshot collect_context_validity_snapshot();

}  // namespace duckdetector::selinux

#endif  // DUCKDETECTOR_SELINUX_CONTEXT_VALIDITY_PROBE_H
