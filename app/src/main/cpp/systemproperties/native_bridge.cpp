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

#include "systemproperties/boot_param_utils.h"
#include "systemproperties/prop_area_probe.h"
#include "systemproperties/property_utils.h"
#include "systemproperties/readonly_serial_probe.h"

#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

    std::set<std::string> interesting_boot_keys(const std::vector<std::string> &properties) {
        std::set<std::string> keys;
        for (const std::string &property: properties) {
            if (!property.starts_with("ro.boot.")) {
                continue;
            }
            keys.insert("androidboot." + property.substr(sizeof("ro.boot.") - 1));
        }
        return keys;
    }

    std::vector<std::string> read_requested_properties(JNIEnv *env, jobjectArray property_names) {
        std::vector<std::string> properties;
        if (property_names == nullptr) {
            return properties;
        }

        const jsize count = env->GetArrayLength(property_names);
        properties.reserve(static_cast<size_t>(count));
        for (jsize index = 0; index < count; ++index) {
            auto *java_property = static_cast<jstring>(env->GetObjectArrayElement(property_names,
                                                                                  index));
            if (java_property == nullptr) {
                continue;
            }

            const char *chars = env->GetStringUTFChars(java_property, nullptr);
            if (chars != nullptr) {
                properties.emplace_back(chars);
                env->ReleaseStringUTFChars(java_property, chars);
            }
            env->DeleteLocalRef(java_property);
        }
        return properties;
    }

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_systemproperties_data_native_SystemPropertiesNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject,
        jobjectArray property_names
) {
    const std::vector<std::string> properties = read_requested_properties(env, property_names);
    const auto libc_properties = systemproperties::read_system_properties(properties);
    const std::string raw_cmdline = systemproperties::read_text_file("/proc/cmdline", 8192);
    const std::string raw_bootconfig = systemproperties::read_text_file("/proc/bootconfig", 8192);
    const std::set<std::string> boot_keys = interesting_boot_keys(properties);
    const auto cmdline_params = systemproperties::parse_cmdline_params(raw_cmdline, boot_keys);
    const auto bootconfig_params = systemproperties::parse_bootconfig_params(raw_bootconfig,
                                                                             boot_keys);
    const auto prop_area_snapshot = systemproperties::scan_prop_area_holes();
    const auto readonly_serial_snapshot =
            systemproperties::scan_readonly_property_serials(properties);

    std::ostringstream output;
    output << "AVAILABLE=1\n";
    output << "RAW_CMDLINE=" << systemproperties::escape_value(raw_cmdline) << "\n";
    output << "RAW_BOOTCONFIG=" << systemproperties::escape_value(raw_bootconfig) << "\n";
    output << "PROP_AREA_AVAILABLE=" << (prop_area_snapshot.available ? 1 : 0) << "\n";
    output << "PROP_AREA_CONTEXTS=" << prop_area_snapshot.context_count << "\n";
    output << "PROP_AREA_HOLES=" << prop_area_snapshot.hole_count << "\n";
    output << "RO_SERIAL_AVAILABLE=" << (readonly_serial_snapshot.available ? 1 : 0) << "\n";
    output << "RO_SERIAL_CHECKED=" << readonly_serial_snapshot.checked_count << "\n";
    output << "RO_SERIAL_FINDINGS=" << readonly_serial_snapshot.finding_count << "\n";

    for (const auto &[key, value]: libc_properties) {
        output << "PROP=" << key << "|" << systemproperties::escape_value(value) << "\n";
    }
    for (const auto &[key, value]: cmdline_params) {
        output << "CMDLINE=" << key << "|" << systemproperties::escape_value(value) << "\n";
    }
    for (const auto &[key, value]: bootconfig_params) {
        output << "BOOTCONFIG=" << key << "|" << systemproperties::escape_value(value) << "\n";
    }
    for (const auto &finding: prop_area_snapshot.findings) {
        output
                << "PROP_AREA_FINDING="
                << finding.context
                << '|'
                << finding.hole_count
                << '|'
                << systemproperties::escape_value(finding.detail)
                << "\n";
    }
    for (const auto &finding: readonly_serial_snapshot.findings) {
        output
                << "RO_SERIAL_FINDING="
                << finding.property
                << '|'
                << finding.suspicious_sample_count
                << '|'
                << finding.low24_hex
                << '|'
                << systemproperties::escape_value(finding.detail)
                << "\n";
    }

    return to_jstring(env, output.str());
}
