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

#include <string>

#include "nativeroot/common/codec.h"
#include "nativeroot/probes/throne_hunt_watch_probe.h"

namespace {

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

    std::string from_jstring(JNIEnv *env, jstring value) {
        if (value == nullptr) {
            return {};
        }
        const char *chars = env->GetStringUTFChars(value, nullptr);
        if (chars == nullptr) {
            return {};
        }
        std::string result(chars);
        env->ReleaseStringUTFChars(value, chars);
        return result;
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_ThroneHuntWatchNativeBridge_nativeInstallWatch(
        JNIEnv *env,
        jobject,
        jstring package_directory
) {
    const auto result = duckdetector::nativeroot::install_throne_hunt_watch(
            from_jstring(env, package_directory)
    );
    return to_jstring(env, duckdetector::nativeroot::encode_throne_hunt_watch(result));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_ThroneHuntWatchNativeBridge_nativeDrainWatch(
        JNIEnv *env,
        jobject,
        jint watch_descriptor
) {
    return to_jstring(
            env,
            duckdetector::nativeroot::encode_throne_hunt_event_summary(
                    duckdetector::nativeroot::drain_throne_hunt_watch(watch_descriptor)
            )
    );
}

extern "C" JNIEXPORT void JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_ThroneHuntWatchNativeBridge_nativeResetWatch(
        JNIEnv *,
        jobject,
        jint watch_descriptor
) {
    duckdetector::nativeroot::reset_throne_hunt_watch(watch_descriptor);
}
