/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

#include "common/payload_codec.h"
#include "nativeroot/probes/initrc_timing_probe.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_InitRcTimingNativeBridge_nativeCollect(
        JNIEnv *env, jobject, jstring directory) {
    if (!directory) return nullptr;
    const char *path = env->GetStringUTFChars(directory, nullptr);
    if (!path) return nullptr;
    const auto result = duckdetector::nativeroot::collect_initrc_timing(path);
    env->ReleaseStringUTFChars(directory, path);
    std::ostringstream payload;
    auto field = [&](const char *key, auto value) {
        payload << key << '=' << duckdetector::common::escape_payload_value(std::to_string(value)) << '\n';
    };
    field("VERSION", 1);
    field("STAGE", static_cast<int>(result.stage));
    field("ERROR", result.error);
    field("CLEANUP_ERROR", result.cleanup_error);
    field("CLEANUP", result.cleanup_complete ? 1 : 0);
    field("CPU", result.cpu);
    field("ITERATIONS", duckdetector::nativeroot::kInitRcIterations);
    field("COUNT", result.count);
    for (std::size_t i = 0; i < result.count; ++i) {
        payload << "ROUND=";
        for (std::size_t condition = 0; condition < 4; ++condition) {
            if (condition) payload << '\t';
            payload << duckdetector::common::escape_payload_value(std::to_string(result.rounds[i][condition]));
        }
        payload << '\n';
    }
    return env->NewStringUTF(payload.str().c_str());
}
