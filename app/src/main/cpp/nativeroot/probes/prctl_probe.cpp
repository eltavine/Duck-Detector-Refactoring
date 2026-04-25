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

#include "nativeroot/probes/prctl_probe.h"

#include <cerrno>
#include <cstdio>
#include <string>
#include <sys/prctl.h>

namespace duckdetector::nativeroot {
    namespace {

        constexpr unsigned long kKernelSuMagic = 0xDEADBEEF;
        constexpr int kKernelSuVersionCommand = 2;
        constexpr int kAlternativeCommands[] = {0, 1, 3, 4, 10};

        Finding build_prctl_finding(
                const std::string &value,
                const std::string &detail,
                const Severity severity
        ) {
            return Finding{
                    .group = "SYSCALL",
                    .label = "KernelSU prctl",
                    .value = value,
                    .detail = detail,
                    .severity = severity,
            };
        }

    }  // namespace

    ProbeResult run_prctl_probe() {
        ProbeResult result;

        errno = 0;
        const long version = prctl(kKernelSuMagic, kKernelSuVersionCommand, 0, 0, 0);
        if (version > 0) {
            result.flags.kernel_su = true;
            result.hit_count = 1;
            result.numeric_value = version;
            result.findings.push_back(
                    build_prctl_finding(
                            "v" + std::to_string(version),
                            "prctl(0xDEADBEEF, 2) returned KernelSU version " +
                            std::to_string(version) + ".",
                            Severity::kDanger
                    )
            );
            return result;
        }

        const int primary_errno = errno;
        if (primary_errno != 0 && primary_errno != EINVAL && primary_errno != ENOSYS) {
            result.hit_count += 1;
            result.findings.push_back(
                    build_prctl_finding(
                            "errno=" + std::to_string(primary_errno),
                            "KernelSU magic prctl returned an unexpected errno instead of EINVAL/ENOSYS.",
                            Severity::kWarning
                    )
            );
        }

        for (const int command: kAlternativeCommands) {
            errno = 0;
            const long response = prctl(kKernelSuMagic, command, 0, 0, 0);
            if (response >= 0 && errno == 0) {
                result.flags.kernel_su = true;
                result.hit_count += 1;
                result.numeric_value = response > 0 ? response : result.numeric_value;
                char detail[160];
                std::snprintf(
                        detail,
                        sizeof(detail),
                        "KernelSU magic prctl accepted alternative command %d and returned %ld.",
                        command,
                        response
                );
                result.findings.push_back(
                        build_prctl_finding(
                                command == kKernelSuVersionCommand && response > 0 ? "v" +
                                                                                     std::to_string(
                                                                                             response)
                                                                                   : "Response",
                                detail,
                                Severity::kDanger
                        )
                );
                break;
            }
        }

        return result;
    }

}  // namespace duckdetector::nativeroot
