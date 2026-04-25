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
#include "nativeroot/snapshot_builder.h"

namespace {

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_NativeRootNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject,
        jboolean skip_ksu_supercall
) {
    return to_jstring(
            env,
            duckdetector::nativeroot::encode_snapshot(
                    duckdetector::nativeroot::collect_snapshot(skip_ksu_supercall == JNI_TRUE)
            )
    );
}
