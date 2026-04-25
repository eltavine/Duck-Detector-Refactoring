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
#include <vector>

#include "playintegrityfix/common/codec.h"
#include "playintegrityfix/snapshot_builder.h"

namespace {

    std::vector<std::string> read_property_names(
            JNIEnv *env,
            jobjectArray property_names
    ) {
        std::vector<std::string> keys;
        if (property_names == nullptr) {
            return keys;
        }

        const jsize count = env->GetArrayLength(property_names);
        keys.reserve(static_cast<size_t>(count));
        for (jsize index = 0; index < count; ++index) {
            auto *java_key = static_cast<jstring>(env->GetObjectArrayElement(property_names,
                                                                             index));
            if (java_key == nullptr) {
                continue;
            }

            const char *chars = env->GetStringUTFChars(java_key, nullptr);
            if (chars != nullptr) {
                keys.emplace_back(chars);
                env->ReleaseStringUTFChars(java_key, chars);
            }
            env->DeleteLocalRef(java_key);
        }
        return keys;
    }

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_playintegrityfix_data_native_PlayIntegrityFixNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject,
        jobjectArray property_names
) {
    return to_jstring(
            env,
            duckdetector::playintegrityfix::encode_snapshot(
                    duckdetector::playintegrityfix::collect_snapshot(
                            read_property_names(env, property_names))
            )
    );
}
