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

#include "zygisk/probes/fd_trap.h"

extern "C" JNIEXPORT jint JNICALL
Java_com_eltavine_duckdetector_features_zygisk_data_fdtrap_ZygiskFdTrapNativeBridge_nativeSetupTrapFd(
        JNIEnv *env,
        jobject,
        jstring cache_dir
) {
    const char *raw_cache_dir = env->GetStringUTFChars(cache_dir, nullptr);
    const std::string path = raw_cache_dir == nullptr ? std::string() : std::string(raw_cache_dir);
    if (raw_cache_dir != nullptr) {
        env->ReleaseStringUTFChars(cache_dir, raw_cache_dir);
    }
    return duckdetector::zygisk::setup_trap_fd(path);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_eltavine_duckdetector_features_zygisk_data_fdtrap_ZygiskFdTrapNativeBridge_nativeVerifyTrapFd(
        JNIEnv *,
        jobject,
        jint fd
) {
    return duckdetector::zygisk::verify_trap_fd(fd);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_zygisk_data_fdtrap_ZygiskFdTrapNativeBridge_nativeGetTrapDetails(
        JNIEnv *env,
        jobject
) {
    return env->NewStringUTF(duckdetector::zygisk::get_trap_details().c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_eltavine_duckdetector_features_zygisk_data_fdtrap_ZygiskFdTrapNativeBridge_nativeCleanupTrapFd(
        JNIEnv *,
        jobject,
        jint fd
) {
    duckdetector::zygisk::cleanup_trap_fd(fd);
}
