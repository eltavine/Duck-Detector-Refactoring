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

#include <jni.h>

#include <exception>
#include <optional>
#include <sstream>
#include <string>

#include "selinux/context_validity_probe.h"

namespace {

    std::string escape_value(const std::string &value) {
        std::string escaped;
        escaped.reserve(value.size());
        for (const char ch: value) {
            switch (ch) {
                case '\\':
                    escaped += "\\\\";
                    break;
                case '\n':
                    escaped += "\\n";
                    break;
                case '\r':
                    escaped += "\\r";
                    break;
                case '\t':
                    escaped += "\\t";
                    break;
                default:
                    escaped += ch;
                    break;
            }
        }
        return escaped;
    }

    std::string encode_snapshot(
            const duckdetector::selinux::ContextValidityProbeSnapshot &snapshot
    ) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? '1' : '0') << '\n';
        output << "PROBE_ATTEMPTED=" << (snapshot.probe_attempted ? '1' : '0') << '\n';
        if (!snapshot.carrier_context.empty()) {
            output << "CARRIER_CONTEXT=" << escape_value(snapshot.carrier_context) << '\n';
        }
        output << "CARRIER_MATCHES_EXPECTED=" << (snapshot.carrier_matches_expected ? '1' : '0')
               << '\n';
        if (snapshot.selinux_enabled.has_value()) {
            output << "SELINUX_ENABLED=" << (*snapshot.selinux_enabled ? '1' : '0') << '\n';
        }
        if (snapshot.selinux_enforced.has_value()) {
            output << "SELINUX_ENFORCED=" << (*snapshot.selinux_enforced ? '1' : '0') << '\n';
        }
        if (snapshot.pid_context_matches_current.has_value()) {
            output << "PID_CONTEXT_MATCHES_CURRENT="
                   << (*snapshot.pid_context_matches_current ? '1' : '0') << '\n';
        }
        if (snapshot.proc_self_context_matches_current.has_value()) {
            output << "PROC_SELF_CONTEXT_MATCHES_CURRENT="
                   << (*snapshot.proc_self_context_matches_current ? '1' : '0') << '\n';
        }
        if (snapshot.dyntransition_check_passed.has_value()) {
            output << "DYNTRANSITION_CHECK_PASSED="
                   << (*snapshot.dyntransition_check_passed ? '1' : '0') << '\n';
        }
        if (snapshot.carrier_control_valid.has_value()) {
            output << "CARRIER_CONTROL_VALID=" << (*snapshot.carrier_control_valid ? '1' : '0')
                   << '\n';
        }
        if (snapshot.negative_control_rejected.has_value()) {
            output << "NEGATIVE_CONTROL_REJECTED="
                   << (*snapshot.negative_control_rejected ? '1' : '0') << '\n';
        }
        if (snapshot.file_control_valid.has_value()) {
            output << "FILE_CONTROL_VALID=" << (*snapshot.file_control_valid ? '1' : '0')
                   << '\n';
        }
        if (snapshot.file_negative_control_rejected.has_value()) {
            output << "FILE_NEGATIVE_CONTROL_REJECTED="
                   << (*snapshot.file_negative_control_rejected ? '1' : '0') << '\n';
        }
        output << "ORACLE_CONTROLS_PASSED=" << (snapshot.oracle_controls_passed ? '1' : '0')
               << '\n';
        output << "KSU_RESULTS_STABLE=" << (snapshot.ksu_results_stable ? '1' : '0') << '\n';
        if (!snapshot.query_method.empty()) {
            output << "QUERY_METHOD=" << escape_value(snapshot.query_method) << '\n';
        }
        if (snapshot.ksu_domain_valid.has_value()) {
            output << "KSU_DOMAIN_VALID=" << (*snapshot.ksu_domain_valid ? '1' : '0') << '\n';
        }
        if (snapshot.ksu_file_valid.has_value()) {
            output << "KSU_FILE_VALID=" << (*snapshot.ksu_file_valid ? '1' : '0') << '\n';
        }
        output << "DIRTY_POLICY_AVAILABLE=" << (snapshot.dirty_policy.available ? '1' : '0')
               << '\n';
        output << "DIRTY_POLICY_PROBE_ATTEMPTED="
               << (snapshot.dirty_policy.probe_attempted ? '1' : '0') << '\n';
        if (!snapshot.dirty_policy.carrier_context.empty()) {
            output << "DIRTY_POLICY_CARRIER_CONTEXT="
                   << escape_value(snapshot.dirty_policy.carrier_context) << '\n';
        }
        output << "DIRTY_POLICY_CARRIER_MATCHES_EXPECTED="
               << (snapshot.dirty_policy.carrier_matches_expected ? '1' : '0') << '\n';
        output << "DIRTY_POLICY_CONTROLS_PASSED="
               << (snapshot.dirty_policy.controls_passed ? '1' : '0') << '\n';
        output << "DIRTY_POLICY_STABLE=" << (snapshot.dirty_policy.stable ? '1' : '0') << '\n';
        if (!snapshot.dirty_policy.query_method.empty()) {
            output << "DIRTY_POLICY_QUERY_METHOD="
                   << escape_value(snapshot.dirty_policy.query_method) << '\n';
        }
        if (snapshot.dirty_policy.access_control_allowed.has_value()) {
            output << "DIRTY_POLICY_ACCESS_CONTROL_ALLOWED="
                   << (*snapshot.dirty_policy.access_control_allowed ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.negative_control_rejected.has_value()) {
            output << "DIRTY_POLICY_NEGATIVE_CONTROL_REJECTED="
                   << (*snapshot.dirty_policy.negative_control_rejected ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.system_server_execmem_allowed.has_value()) {
            output << "DIRTY_POLICY_SYSTEM_SERVER_EXECMEM_ALLOWED="
                   << (*snapshot.dirty_policy.system_server_execmem_allowed ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.fsck_sys_admin_allowed.has_value()) {
            output << "DIRTY_POLICY_FSCK_SYS_ADMIN_ALLOWED="
                   << (*snapshot.dirty_policy.fsck_sys_admin_allowed ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.shell_su_transition_allowed.has_value()) {
            output << "DIRTY_POLICY_SHELL_SU_TRANSITION_ALLOWED="
                   << (*snapshot.dirty_policy.shell_su_transition_allowed ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.adbd_adbroot_binder_call_allowed.has_value()) {
            output << "DIRTY_POLICY_ADBD_ADBROOT_BINDER_CALL_ALLOWED="
                   << (*snapshot.dirty_policy.adbd_adbroot_binder_call_allowed ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.magisk_binder_call_allowed.has_value()) {
            output << "DIRTY_POLICY_MAGISK_BINDER_CALL_ALLOWED="
                   << (*snapshot.dirty_policy.magisk_binder_call_allowed ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.ksu_file_read_allowed.has_value()) {
            output << "DIRTY_POLICY_KSU_FILE_READ_ALLOWED="
                   << (*snapshot.dirty_policy.ksu_file_read_allowed ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.lsposed_file_read_allowed.has_value()) {
            output << "DIRTY_POLICY_LSPOSED_FILE_READ_ALLOWED="
                   << (*snapshot.dirty_policy.lsposed_file_read_allowed ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.xposed_data_file_read_allowed.has_value()) {
            output << "DIRTY_POLICY_XPOSED_DATA_FILE_READ_ALLOWED="
                   << (*snapshot.dirty_policy.xposed_data_file_read_allowed ? '1' : '0') << '\n';
        }
        if (snapshot.dirty_policy.zygote_adb_data_search_allowed.has_value()) {
            output << "DIRTY_POLICY_ZYGOTE_ADB_DATA_SEARCH_ALLOWED="
                   << (*snapshot.dirty_policy.zygote_adb_data_search_allowed ? '1' : '0') << '\n';
        }
        if (!snapshot.dirty_policy.failure_reason.empty()) {
            output << "DIRTY_POLICY_FAILURE_REASON="
                   << escape_value(snapshot.dirty_policy.failure_reason) << '\n';
        }
        for (const std::string &note: snapshot.dirty_policy.notes) {
            output << "DIRTY_POLICY_NOTE=" << escape_value(note) << '\n';
        }
        if (!snapshot.failure_reason.empty()) {
            output << "FAILURE_REASON=" << escape_value(snapshot.failure_reason) << '\n';
        }
        for (const std::string &note: snapshot.notes) {
            output << "NOTE=" << escape_value(note) << '\n';
        }
        return output.str();
    }

    std::string fallback_snapshot_payload(const std::string &reason) {
        try {
            duckdetector::selinux::ContextValidityProbeSnapshot snapshot;
            snapshot.failure_reason = reason;
            snapshot.notes = {
                    "Native context validity bridge used a fallback payload.",
            };
            snapshot.dirty_policy.failure_reason = reason;
            snapshot.dirty_policy.query_method =
                    "android.os.SELinux.checkSELinuxAccess";
            snapshot.dirty_policy.notes = {
                    "Native context validity bridge used a fallback payload.",
            };
            return encode_snapshot(snapshot);
        } catch (...) {
            return
                    "AVAILABLE=0\n"
                    "PROBE_ATTEMPTED=0\n"
                    "CARRIER_MATCHES_EXPECTED=0\n"
                    "ORACLE_CONTROLS_PASSED=0\n"
                    "KSU_RESULTS_STABLE=0\n"
                    "DIRTY_POLICY_AVAILABLE=0\n"
                    "DIRTY_POLICY_PROBE_ATTEMPTED=0\n"
                    "DIRTY_POLICY_CARRIER_MATCHES_EXPECTED=0\n"
                    "DIRTY_POLICY_CONTROLS_PASSED=0\n"
                    "DIRTY_POLICY_STABLE=0\n"
                    "DIRTY_POLICY_QUERY_METHOD=android.os.SELinux.checkSELinuxAccess\n"
                    "DIRTY_POLICY_FAILURE_REASON=Native context validity bridge fallback failed.\n"
                    "DIRTY_POLICY_NOTE=Native context validity bridge returned a last-resort payload.\n"
                    "FAILURE_REASON=Native context validity bridge fallback failed.\n"
                    "NOTE=Native context validity bridge returned a last-resort payload.\n";
        }
    }

    jstring to_jstring(
            JNIEnv *env,
            const std::string &value
    ) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_selinux_data_native_SelinuxContextValidityBridge_nativeCollectContextValiditySnapshotInternal(
        JNIEnv *env,
        jclass clazz) {
    try {
        return to_jstring(
                env,
                encode_snapshot(
                        duckdetector::selinux::collect_context_validity_snapshot()
                )
        );
    } catch (const std::exception &error) {
        return to_jstring(env, fallback_snapshot_payload(error.what()));
    } catch (...) {
        return to_jstring(
                env,
                fallback_snapshot_payload(
                        "Native context validity bridge failed with an unknown exception."
                )
        );
    }
}
