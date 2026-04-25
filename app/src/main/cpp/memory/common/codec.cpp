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

#include "memory/common/codec.h"

#include <sstream>

namespace duckdetector::memory {

    std::vector<Finding> collect_all_findings(const Snapshot &snapshot) {
        std::vector<Finding> findings;
        findings.reserve(
                snapshot.hooks.findings.size() +
                snapshot.maps.findings.size() +
                snapshot.fd.findings.size() +
                snapshot.signal.findings.size() +
                snapshot.vdso.findings.size() +
                snapshot.linker.findings.size()
        );
        findings.insert(findings.end(), snapshot.hooks.findings.begin(),
                        snapshot.hooks.findings.end());
        findings.insert(findings.end(), snapshot.maps.findings.begin(),
                        snapshot.maps.findings.end());
        findings.insert(findings.end(), snapshot.fd.findings.begin(), snapshot.fd.findings.end());
        findings.insert(findings.end(), snapshot.signal.findings.begin(),
                        snapshot.signal.findings.end());
        findings.insert(findings.end(), snapshot.vdso.findings.begin(),
                        snapshot.vdso.findings.end());
        findings.insert(findings.end(), snapshot.linker.findings.begin(),
                        snapshot.linker.findings.end());
        return findings;
    }

    int count_findings_by_severity(const Snapshot &snapshot, const FindingSeverity severity) {
        int count = 0;
        for (const Finding &finding: collect_all_findings(snapshot)) {
            if (finding.severity == severity) {
                ++count;
            }
        }
        return count;
    }

    const char *to_string(const FindingSeverity severity) {
        switch (severity) {
            case FindingSeverity::kCritical:
                return "CRITICAL";
            case FindingSeverity::kHigh:
                return "HIGH";
            case FindingSeverity::kMedium:
                return "MEDIUM";
            case FindingSeverity::kLow:
                return "LOW";
        }
        return "LOW";
    }

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

    std::string encode_snapshot(const Snapshot &snapshot) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? '1' : '0') << '\n';
        output << "GOT_PLT_HOOK=" << (snapshot.hooks.got_plt_hook ? '1' : '0') << '\n';
        output << "INLINE_HOOK=" << (snapshot.hooks.inline_hook ? '1' : '0') << '\n';
        output << "PROLOGUE_MODIFIED=" << (snapshot.hooks.prologue_modified ? '1' : '0') << '\n';
        output << "TRAMPOLINE=" << (snapshot.hooks.trampoline ? '1' : '0') << '\n';
        output << "SUSPICIOUS_JUMP=" << (snapshot.hooks.suspicious_jump ? '1' : '0') << '\n';
        output << "MODIFIED_FUNCTION_COUNT=" << snapshot.hooks.modified_function_count << '\n';

        output << "WRITABLE_EXEC=" << (snapshot.maps.writable_exec ? '1' : '0') << '\n';
        output << "ANONYMOUS_EXEC=" << (snapshot.maps.anonymous_exec ? '1' : '0') << '\n';
        output << "SWAPPED_EXEC=" << (snapshot.maps.swapped_exec ? '1' : '0') << '\n';
        output << "SHARED_DIRTY_EXEC=" << (snapshot.maps.shared_dirty_exec ? '1' : '0') << '\n';

        output << "DELETED_SO=" << (snapshot.fd.deleted_so ? '1' : '0') << '\n';
        output << "SUSPICIOUS_MEMFD=" << (snapshot.fd.suspicious_memfd ? '1' : '0') << '\n';
        output << "EXEC_ASHMEM=" << (snapshot.fd.exec_ashmem ? '1' : '0') << '\n';
        output << "DEV_ZERO_EXEC=" << (snapshot.fd.dev_zero_exec ? '1' : '0') << '\n';

        output << "SIGNAL_HANDLER=" << (snapshot.signal.suspicious_handler ? '1' : '0') << '\n';
        output << "FRIDA_SIGNAL=" << (snapshot.signal.frida_named_handler ? '1' : '0') << '\n';
        output << "ANONYMOUS_SIGNAL=" << (snapshot.signal.anonymous_handler ? '1' : '0') << '\n';

        output << "VDSO_REMAPPED=" << (snapshot.vdso.remapped ? '1' : '0') << '\n';
        output << "VDSO_UNUSUAL_BASE=" << (snapshot.vdso.unusual_base ? '1' : '0') << '\n';

        output << "DELETED_LIBRARY=" << (snapshot.linker.deleted_library ? '1' : '0') << '\n';
        output << "HIDDEN_MODULE=" << (snapshot.linker.hidden_module ? '1' : '0') << '\n';
        output << "MAPS_ONLY_MODULE=" << (snapshot.linker.maps_only_module ? '1' : '0') << '\n';

        output << "CRITICAL_COUNT="
               << count_findings_by_severity(snapshot, FindingSeverity::kCritical) << '\n';
        output << "HIGH_COUNT=" << count_findings_by_severity(snapshot, FindingSeverity::kHigh)
               << '\n';
        output << "MEDIUM_COUNT=" << count_findings_by_severity(snapshot, FindingSeverity::kMedium)
               << '\n';
        output << "LOW_COUNT=" << count_findings_by_severity(snapshot, FindingSeverity::kLow)
               << '\n';

        for (const Finding &finding: collect_all_findings(snapshot)) {
            output << "FINDING="
                   << finding.section << '\t'
                   << finding.category << '\t'
                   << finding.label << '\t'
                   << to_string(finding.severity) << '\t'
                   << escape_value(finding.detail)
                   << '\n';
        }

        return output.str();
    }

}  // namespace duckdetector::memory
