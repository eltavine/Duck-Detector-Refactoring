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

#include "nativeroot/common/codec.h"

#include <sstream>

namespace duckdetector::nativeroot {
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

    }  // namespace

    const char *to_string(const Severity severity) {
        switch (severity) {
            case Severity::kDanger:
                return "DANGER";
            case Severity::kWarning:
                return "WARNING";
            case Severity::kInfo:
                return "INFO";
        }
        return "INFO";
    }

    void merge_flags(DetectionFlags &target, const DetectionFlags &source) {
        target.kernel_su = target.kernel_su || source.kernel_su;
        target.apatch = target.apatch || source.apatch;
        target.magisk = target.magisk || source.magisk;
        target.susfs = target.susfs || source.susfs;
    }

    std::string encode_snapshot(const Snapshot &snapshot) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? '1' : '0') << '\n';
        output << "KERNELSU=" << (snapshot.flags.kernel_su ? '1' : '0') << '\n';
        output << "APATCH=" << (snapshot.flags.apatch ? '1' : '0') << '\n';
        output << "MAGISK=" << (snapshot.flags.magisk ? '1' : '0') << '\n';
        output << "SUSFS=" << (snapshot.flags.susfs ? '1' : '0') << '\n';
        output << "KSU_VERSION=" << snapshot.kernel_su_version << '\n';
        output << "PRCTL_HIT=" << (snapshot.prctl_probe_hit ? '1' : '0') << '\n';
        output << "KSU_SUPERCALL_ATTEMPTED=" << (snapshot.ksu_supercall_attempted ? '1' : '0')
               << '\n';
        output << "KSU_SUPERCALL_HIT=" << (snapshot.ksu_supercall_probe_hit ? '1' : '0') << '\n';
        output << "KSU_SUPERCALL_BLOCKED=" << (snapshot.ksu_supercall_blocked ? '1' : '0')
               << '\n';
        output << "KSU_SUPERCALL_SAFE_MODE=" << (snapshot.ksu_supercall_safe_mode ? '1' : '0')
               << '\n';
        output << "KSU_SUPERCALL_LKM=" << (snapshot.ksu_supercall_lkm ? '1' : '0') << '\n';
        output << "KSU_SUPERCALL_LATE_LOAD=" << (snapshot.ksu_supercall_late_load ? '1' : '0')
               << '\n';
        output << "KSU_SUPERCALL_PR_BUILD=" << (snapshot.ksu_supercall_pr_build ? '1' : '0')
               << '\n';
        output << "KSU_SUPERCALL_MANAGER=" << (snapshot.ksu_supercall_manager ? '1' : '0')
               << '\n';
        output << "SUSFS_HIT=" << (snapshot.susfs_probe_hit ? '1' : '0') << '\n';
        output << "SELF_SU_DOMAIN=" << (snapshot.self_su_domain ? '1' : '0') << '\n';
        output << "SELF_CONTEXT=" << escape_value(snapshot.self_context) << '\n';
        output << "SELF_KSU_DRIVER_FDS=" << snapshot.self_ksu_driver_fd_count << '\n';
        output << "SELF_KSU_FDWRAPPER_FDS=" << snapshot.self_ksu_fdwrapper_count << '\n';
        output << "PATH_HITS=" << snapshot.path_hit_count << '\n';
        output << "PATH_CHECKS=" << snapshot.path_check_count << '\n';
        output << "PROCESS_HITS=" << snapshot.process_hit_count << '\n';
        output << "PROCESS_CHECKED=" << snapshot.process_checked_count << '\n';
        output << "PROCESS_DENIED=" << snapshot.process_denied_count << '\n';
        output << "KERNEL_HITS=" << snapshot.kernel_hit_count << '\n';
        output << "KERNEL_SOURCES=" << snapshot.kernel_source_count << '\n';
        output << "PROPERTY_HITS=" << snapshot.property_hit_count << '\n';
        output << "PROPERTY_CHECKS=" << snapshot.property_check_count << '\n';
        for (const Finding &finding: snapshot.findings) {
            output << "FINDING="
                   << finding.group << '\t'
                   << to_string(finding.severity) << '\t'
                   << escape_value(finding.label) << '\t'
                   << escape_value(finding.value) << '\t'
                   << escape_value(finding.detail) << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::nativeroot
