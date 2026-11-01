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

#include "selinuxpolicy/context_validity_probe.h"
#include "selinuxpolicy/context_validity_internal.h"
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <optional>
#include <string>
#include <sys/system_properties.h>
#include <utility>
#include <unistd.h>

namespace duckdetector::selinux::detail {

    DirtyPolicyProbeSnapshot collect_dirty_policy_snapshot(
            const LoadedSelinuxSymbols &symbols,
            JNIEnv *env,
            const JavaSelinuxAccess &java_access,
            const std::string &carrier_context,
            const bool carrier_matches_expected,
            const std::optional<bool> &dyntransition_check_passed,
            const bool allow_access_checks
    ) {
        DirtyPolicyProbeSnapshot snapshot;
        snapshot.query_method = kDirtyPolicyQueryMethod;
        snapshot.available = symbols.check_access != nullptr;
        snapshot.carrier_context = carrier_context;
        snapshot.carrier_matches_expected = carrier_matches_expected;
        snapshot.notes.push_back(std::string("Carrier context: ") + carrier_context);
        snapshot.notes.push_back(std::string("Query method: ") + kDirtyPolicyQueryMethod);
        if (!snapshot.available) {
            snapshot.failure_reason = "selinux_check_access unavailable from the current carrier.";
            return snapshot;
        }
        if (!carrier_matches_expected || carrier_context.rfind(kExpectedCarrierPrefix, 0) != 0) {
            snapshot.failure_reason = "Carrier context is not app_zygote.";
            snapshot.notes.push_back("Dirty policy access checks require the dedicated app_zygote carrier.");
            return snapshot;
        }
        if (dyntransition_check_passed.has_value() && !*dyntransition_check_passed) {
            snapshot.failure_reason = "app_zygote dyntransition self-check failed.";
            snapshot.notes.push_back("Dirty policy access checks were skipped because the carrier could not confirm app_zygote -> isolated_app dyntransition.");
            return snapshot;
        }
        if (!allow_access_checks) {
            snapshot.failure_reason =
                    "Skipped: the status page probe did not show libselinux can map /sys/fs/selinux/status safely.";
            return snapshot;
        }

        snapshot.probe_attempted = true;
        ScopedDirtyPolicyAuditMarker audit_marker(symbols);
        if (audit_marker.installed()) {
            snapshot.notes.push_back(
                    std::string("Audit marker: ") + kProbeMarkerPrefix + audit_marker.marker()
            );
        } else {
            snapshot.notes.push_back(
                    "Audit marker unavailable because libselinux audit callback symbols were missing."
            );
        }
        void *auditdata = audit_marker.auditdata();

        const AccessPairResult access_control = check_access_rule_pair(
                symbols,
                kExpectedCarrierPrefix,
                kIsolatedAppContext,
                kProcessClass,
                kDyntransitionPermission,
                auditdata
        );
        const AccessPairResult negative_control = check_access_rule_pair(
                symbols,
                kUntrustedAppContext,
                kDirtyPolicyNegativeControlContext,
                kBinderClass,
                kCallPermission,
                auditdata
        );

        snapshot.access_control_allowed = pair_allowed_value(access_control);
        if (const auto negative_allowed = pair_allowed_value(negative_control); negative_allowed.has_value()) {
            snapshot.negative_control_rejected = !*negative_allowed;
        }
        snapshot.controls_passed = access_control.stable && negative_control.stable &&
                                   access_control.first == std::optional<bool>(true) &&
                                   negative_control.first == std::optional<bool>(false);
        snapshot.stable = access_control.stable && negative_control.stable;

        append_access_note(snapshot, "Access control", access_control);
        append_access_note(snapshot, "Negative control", negative_control);

        const AccessPairResult system_server_execmem = check_access_rule_pair(symbols, kSystemServerContext, kSystemServerContext, kProcessClass, kExecmemPermission, auditdata);
        const AccessPairResult fsck_sys_admin = check_access_rule_pair(symbols, kFsckUntrustedContext, kFsckUntrustedContext, kCapabilityClass, kSysAdminPermission, auditdata);
        const AccessPairResult shell_su_transition = check_access_rule_pair(symbols, kShellContext, kSuContext, kProcessClass, kTransitionPermission, auditdata);
        const AccessPairResult adbd_adbroot_binder_call = check_access_rule_pair(symbols, kAdbdContext, kAdbrootContext, kBinderClass, kCallPermission, auditdata);
        const AccessPairResult magisk_binder_call = check_access_rule_pair(symbols, kUntrustedAppContext, kMagiskContext, kBinderClass, kCallPermission, auditdata);
        const AccessPairResult ksu_file_read = check_access_rule_pair(symbols, kUntrustedAppContext, kKsuFileContext, kFileClass, kReadPermission, auditdata);
        const AccessPairResult lsposed_file_read = check_access_rule_pair(symbols, kUntrustedAppContext, kLsposedFileContext, kFileClass, kReadPermission, auditdata);
        const AccessPairResult magisk_droidspacesd_transition = check_access_rule_pair(symbols, kMagiskContext, kDroidspacesdContext, kProcessClass, kDyntransitionPermission, auditdata);
        const AccessPairResult su_droidspacesd_transition = check_access_rule_pair(symbols, kSuContext, kDroidspacesdContext, kProcessClass, kDyntransitionPermission, auditdata);
        const AccessPairResult system_server_droidspacesd_binder_call = check_access_rule_pair(symbols, kSystemServerContext, kDroidspacesdContext, kBinderClass, kCallPermission, auditdata);
        const AccessPairResult msd_app_daemon_connect = check_access_rule_pair(symbols, kMsdAppContext, kMsdDaemonContext, kUnixStreamSocketClass, kConnectToPermission, auditdata);
        const AccessPairResult msd_daemon_self_connect = check_access_rule_pair(symbols, kMsdDaemonContext, kMsdDaemonContext, kUnixStreamSocketClass, kConnectToPermission, auditdata);
        const AccessPairResult msd_daemon_selinuxfs_read = check_access_rule_pair(symbols, kMsdDaemonContext, kSelinuxfsContext, kFileClass, kReadPermission, auditdata);
        const AccessPairResult msd_daemon_configfs_dir_search = check_access_rule_pair(symbols, kMsdDaemonContext, kConfigfsContext, kDirClass, kSearchPermission, auditdata);
        const AccessPairResult msd_daemon_configfs_file_write = check_access_rule_pair(symbols, kMsdDaemonContext, kConfigfsContext, kFileClass, kWritePermission, auditdata);
        const AccessPairResult xposed_data_file_read = check_access_rule_pair(symbols, kUntrustedAppContext, kXposedDataContext, kFileClass, kReadPermission, auditdata);
        const AccessPairResult zygote_adb_data_search = check_access_rule_pair(symbols, kZygoteContext, kAdbDataFileContext, kDirClass, kSearchPermission, auditdata);

        snapshot.system_server_execmem_allowed = pair_allowed_value(system_server_execmem);
        snapshot.fsck_sys_admin_allowed = pair_allowed_value(fsck_sys_admin);
        if (is_user_build()) {
            snapshot.shell_su_transition_allowed = pair_allowed_value(shell_su_transition);
        }
        snapshot.adbd_adbroot_binder_call_allowed = pair_allowed_value(adbd_adbroot_binder_call);
        snapshot.magisk_binder_call_allowed = pair_allowed_value(magisk_binder_call);
        snapshot.ksu_file_read_allowed = pair_allowed_value(ksu_file_read);
        snapshot.lsposed_file_read_allowed = pair_allowed_value(lsposed_file_read);
        snapshot.magisk_droidspacesd_transition_allowed = pair_allowed_value(magisk_droidspacesd_transition);
        snapshot.su_droidspacesd_transition_allowed = pair_allowed_value(su_droidspacesd_transition);
        snapshot.system_server_droidspacesd_binder_call_allowed = pair_allowed_value(system_server_droidspacesd_binder_call);
        snapshot.msd_app_daemon_connect_allowed = pair_allowed_value(msd_app_daemon_connect);
        snapshot.msd_daemon_self_connect_allowed = pair_allowed_value(msd_daemon_self_connect);
        snapshot.msd_daemon_selinuxfs_read_allowed = pair_allowed_value(msd_daemon_selinuxfs_read);
        snapshot.msd_daemon_configfs_dir_search_allowed = pair_allowed_value(msd_daemon_configfs_dir_search);
        snapshot.msd_daemon_configfs_file_write_allowed = pair_allowed_value(msd_daemon_configfs_file_write);
        snapshot.xposed_data_file_read_allowed = pair_allowed_value(xposed_data_file_read);
        snapshot.zygote_adb_data_search_allowed = pair_allowed_value(zygote_adb_data_search);

        snapshot.stable = snapshot.stable &&
                          system_server_execmem.stable &&
                          fsck_sys_admin.stable &&
                          adbd_adbroot_binder_call.stable &&
                          magisk_binder_call.stable &&
                          ksu_file_read.stable &&
                          lsposed_file_read.stable &&
                          magisk_droidspacesd_transition.stable &&
                          su_droidspacesd_transition.stable &&
                          system_server_droidspacesd_binder_call.stable &&
                          msd_app_daemon_connect.stable &&
                          msd_daemon_self_connect.stable &&
                          msd_daemon_selinuxfs_read.stable &&
                          msd_daemon_configfs_dir_search.stable &&
                          msd_daemon_configfs_file_write.stable &&
                          xposed_data_file_read.stable &&
                          zygote_adb_data_search.stable &&
                          (!is_user_build() || shell_su_transition.stable);

        append_access_note(snapshot, "system_server execmem", system_server_execmem);
        append_access_note(snapshot, "fsck_untrusted sys_admin", fsck_sys_admin);
        if (is_user_build()) {
            append_access_note(snapshot, "shell -> su transition", shell_su_transition);
        } else {
            snapshot.notes.push_back("shell -> su transition skipped because ro.build.type is not user.");
        }
        append_access_note(snapshot, "adbd -> adbroot binder", adbd_adbroot_binder_call);
        append_access_note(snapshot, "untrusted_app -> magisk binder", magisk_binder_call);
        append_access_note(snapshot, "untrusted_app -> ksu_file read", ksu_file_read);
        append_access_note(snapshot, "untrusted_app -> lsposed_file read", lsposed_file_read);
        append_access_note(snapshot, "magisk -> droidspacesd dyntransition", magisk_droidspacesd_transition);
        append_access_note(snapshot, "su -> droidspacesd dyntransition", su_droidspacesd_transition);
        append_access_note(snapshot, "system_server -> droidspacesd binder", system_server_droidspacesd_binder_call);
        append_access_note(snapshot, "msd_app -> msd_daemon connectto", msd_app_daemon_connect);
        append_access_note(snapshot, "msd_daemon -> msd_daemon connectto", msd_daemon_self_connect);
        append_access_note(snapshot, "msd_daemon -> selinuxfs read", msd_daemon_selinuxfs_read);
        append_access_note(snapshot, "msd_daemon -> configfs dir search", msd_daemon_configfs_dir_search);
        append_access_note(snapshot, "msd_daemon -> configfs file write", msd_daemon_configfs_file_write);
        append_access_note(snapshot, "untrusted_app -> xposed_data read", xposed_data_file_read);
        append_access_note(snapshot, "zygote -> adb_data_file search", zygote_adb_data_search);

        struct ExtraRule {
            const char *name;
            const char *source;
            const char *target;
            const char *clazz;
            const char *permission;
        };
        const ExtraRule extra_rules[] = {
                {"rootfs -> tmpfs associate", "u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate"},
                {"kernel -> tmpfs fifo open", "u:r:kernel:s0", "u:object_r:tmpfs:s0", "fifo_file", "open"},
                {"kernel -> adb_data_file read", "u:r:kernel:s0", "u:object_r:adb_data_file:s0", "file", "read"},
                {"system_server -> apk_data_file execute", "u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"},
                {"dex2oat -> dex2oat_exec execute_no_trans", "u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans"},
        };
        for (const auto &rule: extra_rules) {
            const auto result = check_access_rule_pair(
                    symbols, rule.source, rule.target, rule.clazz, rule.permission, auditdata
            );
            // Optional 2.2 rules must not invalidate the pre-existing oracle's trust.
            // Each extra edge is published only when its own pair is stable.
            if (const auto allowed = pair_allowed_value(result); allowed.has_value()) {
                snapshot.additional_rules[rule.name] = *allowed;
            }
            append_access_note(snapshot, rule.name, result);
        }

        if (!snapshot.stable) {
            snapshot.failure_reason = "Dirty policy oracle repeated inconsistently.";
        } else if (!snapshot.controls_passed) {
            snapshot.failure_reason = "Dirty policy oracle self-test failed.";
        }
        return snapshot;
    }

}  // namespace duckdetector::selinux::detail
