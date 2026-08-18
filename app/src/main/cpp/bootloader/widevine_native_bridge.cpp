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
#include <media/NdkMediaDrm.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace {

    // Widevine securityLevel and systemId are short ASCII properties.
    constexpr size_t MAX_PROPERTY_VALUE_LENGTH = 64;

    constexpr std::array<uint8_t, 16> WIDEVINE_UUID = {
            0xed, 0xef, 0x8b, 0xa9,
            0x79, 0xd6,
            0x4a, 0xce,
            0xa3, 0xc8,
            0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
    };

    struct MediaDrmReleaser {
        void operator()(AMediaDrm *media_drm) const {
            if (media_drm != nullptr) {
                AMediaDrm_release(media_drm);
            }
        }
    };

    using MediaDrmPtr = std::unique_ptr<AMediaDrm, MediaDrmReleaser>;

    bool copy_property_value(const char *value, std::string *output) {
        if (value == nullptr || output == nullptr) {
            return false;
        }
        output->clear();
        for (size_t index = 0; index <= MAX_PROPERTY_VALUE_LENGTH; ++index) {
            const auto character = static_cast<unsigned char>(value[index]);
            if (character == '\0') {
                return index > 0;
            }
            if (index == MAX_PROPERTY_VALUE_LENGTH || character < 0x20 || character > 0x7e) {
                output->clear();
                return false;
            }
            output->push_back(static_cast<char>(character));
        }
        output->clear();
        return false;
    }

    bool set_string(JNIEnv *env, jobjectArray output, jsize index, const std::string &value) {
        jstring java_value = env->NewStringUTF(value.c_str());
        if (java_value == nullptr) {
            return false;
        }
        env->SetObjectArrayElement(output, index, java_value);
        env->DeleteLocalRef(java_value);
        return !env->ExceptionCheck();
    }

}  // namespace

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_eltavine_duckdetector_features_bootloader_data_widevine_WidevineNativeBridge_nativeReadProperties(
        JNIEnv *env,
        jobject
) {
    jclass string_class = env->FindClass("java/lang/String");
    if (string_class == nullptr) {
        return nullptr;
    }

    jobjectArray output = env->NewObjectArray(5, string_class, nullptr);
    env->DeleteLocalRef(string_class);
    if (output == nullptr) {
        return nullptr;
    }

    if (!AMediaDrm_isCryptoSchemeSupported(WIDEVINE_UUID.data(), nullptr)) {
        if (!set_string(env, output, 0, "0")) {
            return nullptr;
        }
        return output;
    }

    MediaDrmPtr media_drm(AMediaDrm_createByUUID(WIDEVINE_UUID.data()));
    if (media_drm == nullptr) {
        if (!set_string(env, output, 0, "0")) {
            return nullptr;
        }
        return output;
    }

    const char *security_level_pointer = nullptr;
    media_status_t security_level_status = AMediaDrm_getPropertyString(
            media_drm.get(),
            "securityLevel",
            &security_level_pointer
    );
    std::string security_level;
    if (security_level_status == AMEDIA_OK &&
        !copy_property_value(security_level_pointer, &security_level)) {
        security_level_status = AMEDIA_ERROR_MALFORMED;
    }

    const char *system_id_pointer = nullptr;
    media_status_t system_id_status = AMediaDrm_getPropertyString(
            media_drm.get(),
            "systemId",
            &system_id_pointer
    );
    std::string system_id;
    if (system_id_status == AMEDIA_OK &&
        !copy_property_value(system_id_pointer, &system_id)) {
        system_id_status = AMEDIA_ERROR_MALFORMED;
    }

    if (!set_string(env, output, 0, "1") ||
        !set_string(env, output, 1, std::to_string(security_level_status))) {
        return nullptr;
    }
    if (security_level_status == AMEDIA_OK) {
        if (!set_string(env, output, 2, security_level)) {
            return nullptr;
        }
    }
    if (!set_string(env, output, 3, std::to_string(system_id_status))) {
        return nullptr;
    }
    if (system_id_status == AMEDIA_OK) {
        if (!set_string(env, output, 4, system_id)) {
            return nullptr;
        }
    }
    return output;
}
