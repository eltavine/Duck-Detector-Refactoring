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

#include <sstream>
#include <string>

#include "selinux/audit_probe.h"

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

    std::string encode_snapshot(const duckdetector::selinux::AuditProbeSnapshot &snapshot) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? '1' : '0') << '\n';
        output << "CALLBACK_INSTALLED=" << (snapshot.callback_installed ? '1' : '0') << '\n';
        output << "PROBE_RAN=" << (snapshot.probe_ran ? '1' : '0') << '\n';
        output << "DENIAL_OBSERVED=" << (snapshot.denial_observed ? '1' : '0') << '\n';
        output << "ALLOW_OBSERVED=" << (snapshot.allow_observed ? '1' : '0') << '\n';
        if (!snapshot.probe_marker.empty()) {
            output << "PROBE_MARKER=" << escape_value(snapshot.probe_marker) << '\n';
        }
        if (!snapshot.failure_reason.empty()) {
            output << "FAILURE_REASON=" << escape_value(snapshot.failure_reason) << '\n';
        }
        for (const std::string &line: snapshot.callback_lines) {
            output << "LINE=" << escape_value(line) << '\n';
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
Java_com_eltavine_duckdetector_features_selinux_data_native_SelinuxNativeAuditBridge_nativeCollectAuditSnapshot(
        JNIEnv *env,
        jobject
) {
    return to_jstring(env, encode_snapshot(duckdetector::selinux::collect_audit_snapshot()));
}
