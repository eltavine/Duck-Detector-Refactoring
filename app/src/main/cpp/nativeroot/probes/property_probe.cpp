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

#include "nativeroot/probes/property_probe.h"

#include <string>

#include "nativeroot/common/io_utils.h"

namespace duckdetector::nativeroot {
    namespace {

        struct PropertyRule {
            const char *name;
            const char *label;
            bool kernel_su;
            bool apatch;
            bool magisk;
            Severity severity;
        };

        constexpr PropertyRule kPropertyRules[] = {
                {"ro.kernel.ksu",     "KernelSU property",         true,  false, false, Severity::kDanger},
                {"ro.ksu.version",    "KernelSU version property", true,  false, false, Severity::kDanger},
                {"ro.kernel.apatch",  "APatch property",           false, true,  false, Severity::kWarning},
                {"ro.apatch.version", "APatch version property",   false, true,  false, Severity::kWarning},
                {"ro.kernel.kpatch",  "KernelPatch property",      false, true,  false, Severity::kWarning},
        };

        std::string badge_value(const std::string &value) {
            return value.size() > 18 ? "Set" : value;
        }

    }  // namespace

    ProbeResult run_property_probe() {
        ProbeResult result;
        result.checked_count = static_cast<int>(sizeof(kPropertyRules) / sizeof(kPropertyRules[0]));

        for (const PropertyRule &rule: kPropertyRules) {
            const std::string value = read_property_value(rule.name);
            if (value.empty()) {
                continue;
            }
            result.flags.kernel_su = result.flags.kernel_su || rule.kernel_su;
            result.flags.apatch = result.flags.apatch || rule.apatch;
            result.flags.magisk = result.flags.magisk || rule.magisk;
            result.hit_count += 1;
            result.findings.push_back(
                    Finding{
                            .group = "PROPERTY",
                            .label = rule.label,
                            .value = badge_value(value),
                            .detail = std::string(rule.name) + "=" + value,
                            .severity = rule.severity,
                    }
            );
        }

        return result;
    }

}  // namespace duckdetector::nativeroot
