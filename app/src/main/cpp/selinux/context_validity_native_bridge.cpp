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
        if (!snapshot.bit_pair.empty()) {
            output << "BIT_PAIR=" << escape_value(snapshot.bit_pair) << '\n';
        }
        if (!snapshot.failure_reason.empty()) {
            output << "FAILURE_REASON=" << escape_value(snapshot.failure_reason) << '\n';
        }
        for (const std::string &note: snapshot.notes) {
            output << "NOTE=" << escape_value(note) << '\n';
        }
        return output.str();
    }

    jstring to_jstring(
            JNIEnv *env,
            const std::string &value
    ) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_selinux_data_native_SelinuxContextValidityBridge_nativeCollectContextValiditySnapshot(
        JNIEnv *env,
        jobject
) {
    return to_jstring(
            env,
            encode_snapshot(duckdetector::selinux::collect_context_validity_snapshot())
    );
}
