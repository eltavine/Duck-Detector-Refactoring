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

#include <string>

#include "mount/detector_core.h"

namespace {

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_mount_data_native_MountNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject,
        jstring externalStorageRoot
) {
    std::string root;
    if (externalStorageRoot != nullptr) {
        const char *value = env->GetStringUTFChars(externalStorageRoot, nullptr);
        if (value == nullptr) return nullptr;
        root = value;
        env->ReleaseStringUTFChars(externalStorageRoot, value);
    }
    const duckdetector::mount::MountSnapshot snapshot = duckdetector::mount::collect_snapshot(root);
    return to_jstring(env, duckdetector::mount::encode_snapshot(snapshot));
}
