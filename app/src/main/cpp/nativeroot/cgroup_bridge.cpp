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

#include "nativeroot/probes/cgroup_process_probe.h"

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
                case '\0':
                    escaped += "\\0";
                    break;
                default:
                    escaped += ch;
                    break;
            }
        }
        return escaped;
    }

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_CgroupProcessLeakNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject
) {
    const auto snapshot = duckdetector::nativeroot::collect_cgroup_leak_snapshot();

    std::ostringstream output;
    output << "AVAILABLE=" << (snapshot.available ? '1' : '0') << '\n';
    output << "PATH_CHECKS=" << snapshot.path_check_count << '\n';
    output << "PATH_ACCESSIBLE=" << snapshot.accessible_path_count << '\n';
    output << "PROCESS_COUNT=" << snapshot.process_count << '\n';
    output << "PROC_DENIED=" << snapshot.proc_denied_count << '\n';
    for (const auto &path: snapshot.paths) {
        output << "PATH="
               << escape_value(path.path) << '\t'
               << path.uid << '\t'
               << (path.accessible ? '1' : '0') << '\t'
               << path.pid_count << '\n';
    }
    for (const auto &entry: snapshot.entries) {
        output << "ENTRY="
               << escape_value(entry.uid_path) << '\t'
               << entry.cgroup_uid << '\t'
               << entry.pid << '\t'
               << entry.proc_uid << '\t'
               << entry.starttime_ticks << '\t'
               << entry.kill_errno << '\t'
               << entry.getsid_value << '\t'
               << entry.getsid_errno << '\t'
               << entry.getpgid_value << '\t'
               << entry.getpgid_errno << '\t'
               << entry.sched_policy << '\t'
               << entry.sched_errno << '\t'
               << entry.pidfd_errno << '\t'
               << escape_value(entry.proc_context) << '\t'
               << escape_value(entry.comm) << '\t'
               << escape_value(entry.cmdline) << '\n';
    }

    return to_jstring(env, output.str());
}
