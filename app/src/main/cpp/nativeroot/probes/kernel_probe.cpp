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

#include "nativeroot/probes/kernel_probe.h"

#include <set>
#include <sstream>
#include <string>
#include <sys/utsname.h>

#include "nativeroot/common/io_utils.h"

namespace duckdetector::nativeroot {
    namespace {

        constexpr const char *kKernelTokens[] = {
                "ksu_",
                "kernelsu",
                "apatch",
                "kpatch",
                "supercall",
                "magisk",
        };

        void apply_token_flags(const std::string &token, DetectionFlags &flags) {
            if (token.find("ksu") != std::string::npos ||
                token.find("kernelsu") != std::string::npos) {
                flags.kernel_su = true;
            }
            if (token.find("apatch") != std::string::npos ||
                token.find("kpatch") != std::string::npos ||
                token.find("supercall") != std::string::npos) {
                flags.apatch = true;
            }
            if (token.find("magisk") != std::string::npos) {
                flags.magisk = true;
            }
        }

        std::vector<std::string> collect_matches(const std::string &haystack) {
            std::set<std::string> matches;
            for (const char *token: kKernelTokens) {
                if (contains_ignore_case(haystack, token)) {
                    matches.insert(token);
                }
            }
            return std::vector<std::string>(matches.begin(), matches.end());
        }

        void append_source_finding(
                ProbeResult &result,
                const char *label,
                const char *detail_prefix,
                const std::vector<std::string> &matches
        ) {
            if (matches.empty()) {
                return;
            }
            result.hit_count += 1;
            std::ostringstream detail;
            detail << detail_prefix << ": ";
            for (size_t index = 0; index < matches.size(); ++index) {
                if (index > 0) {
                    detail << ", ";
                }
                detail << matches[index];
                apply_token_flags(matches[index], result.flags);
            }
            result.findings.push_back(
                    Finding{
                            .group = "KERNEL",
                            .label = label,
                            .value = std::to_string(matches.size()) + " hit(s)",
                            .detail = detail.str(),
                            .severity = Severity::kWarning,
                    }
            );
        }

    }  // namespace

    ProbeResult run_kernel_probe() {
        ProbeResult result;
        result.checked_count = 3;

        const std::string kallsyms = read_text_file("/proc/kallsyms", 196608);
        append_source_finding(result, "Kernel symbols", "/proc/kallsyms matched",
                              collect_matches(kallsyms));

        const std::string modules = read_text_file("/proc/modules", 32768);
        append_source_finding(result, "Kernel modules", "/proc/modules matched",
                              collect_matches(modules));

        struct utsname uts{};
        if (uname(&uts) == 0) {
            std::string identity(uts.release);
            identity.push_back('\n');
            identity += uts.version;
            append_source_finding(result, "Kernel identity", "uname matched",
                                  collect_matches(identity));
        }

        return result;
    }

}  // namespace duckdetector::nativeroot
