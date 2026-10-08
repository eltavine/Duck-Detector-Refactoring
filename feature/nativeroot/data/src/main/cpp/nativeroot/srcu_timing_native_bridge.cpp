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
#include <string>

#include "common/payload_codec.h"
#include "nativeroot/probes/srcu_close_probe.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_SrcuTimingNativeBridge_nativeMeasureWindow(
        JNIEnv *env, jobject, jstring directory, jobject trigger) {
    if (!directory || !trigger) return nullptr;
    const char *path = env->GetStringUTFChars(directory, nullptr);
    if (!path) return nullptr;
    const auto runnable = env->FindClass("java/lang/Runnable");
    const auto run = runnable ? env->GetMethodID(runnable, "run", "()V") : nullptr;
    if (!run) { env->ReleaseStringUTFChars(directory, path); return nullptr; }
    const auto window = duckdetector::nativeroot::measure_close_window(path, [&] {
        env->CallVoidMethod(trigger, run);
    });
    env->ReleaseStringUTFChars(directory, path);
    env->DeleteLocalRef(runnable);
    if (env->ExceptionCheck()) return nullptr;
    std::ostringstream payload;
    auto field = [&](const char *key, auto value) {
        payload << key << '=' << duckdetector::common::escape_payload_value(std::to_string(value)) << '\n';
    };
    field("VERSION", 1);
    field("BEGIN", window.begin);
    field("END", window.end);
    field("SATURATED", window.saturated ? 1 : 0);
    field("COUNT", window.samples.size());
    for (const auto &sample : window.samples) {
        payload << "SAMPLE=" << duckdetector::common::escape_payload_value(std::to_string(sample.begin))
                << '\t' << duckdetector::common::escape_payload_value(std::to_string(sample.end))
                << '\t' << duckdetector::common::escape_payload_value(std::to_string(static_cast<int>(sample.stage)))
                << '\t' << duckdetector::common::escape_payload_value(std::to_string(sample.error)) << '\n';
    }
    return env->NewStringUTF(payload.str().c_str());
}
