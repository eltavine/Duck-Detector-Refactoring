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

#include "preload/early_detector.h"
#include "preload/virtualization_early_detector.h"

#include <android/log.h>
#include <android/native_activity.h>
#include <jni.h>

#include <cstdint>
#include <string>
#include <time.h>

#define LOG_TAG "MountPreloadEntry"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

    constexpr std::int64_t kSecToNs = 1000000000LL;
    constexpr std::int64_t kDuplicateLaunchWindowNs = kSecToNs;

    std::int64_t g_lastHandoffNs = 0;

    std::int64_t monotonic_now_ns() {
        struct timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        return (static_cast<std::int64_t>(now.tv_sec) * kSecToNs) + now.tv_nsec;
    }

    void finish_activity(JNIEnv *env, jobject activity) {
        jclass activityClass = env->GetObjectClass(activity);
        if (activityClass == nullptr) {
            return;
        }
        jmethodID finish = env->GetMethodID(activityClass, "finish", "()V");
        if (finish != nullptr) {
            env->CallVoidMethod(activity, finish);
        }
        env->DeleteLocalRef(activityClass);
    }

    void put_boolean_extra(JNIEnv *env, jobject intent, jclass intentClass, const char *key,
                           bool value) {
        jmethodID putBooleanExtra = env->GetMethodID(
                intentClass,
                "putExtra",
                "(Ljava/lang/String;Z)Landroid/content/Intent;"
        );
        if (putBooleanExtra == nullptr) {
            return;
        }
        jstring keyString = env->NewStringUTF(key);
        env->CallObjectMethod(intent, putBooleanExtra, keyString, static_cast<jboolean>(value));
        env->DeleteLocalRef(keyString);
    }

    void put_long_extra(JNIEnv *env, jobject intent, jclass intentClass, const char *key,
                        std::int64_t value) {
        jmethodID putLongExtra = env->GetMethodID(
                intentClass,
                "putExtra",
                "(Ljava/lang/String;J)Landroid/content/Intent;"
        );
        if (putLongExtra == nullptr) {
            return;
        }
        jstring keyString = env->NewStringUTF(key);
        env->CallObjectMethod(intent, putLongExtra, keyString, static_cast<jlong>(value));
        env->DeleteLocalRef(keyString);
    }

    void put_string_extra(JNIEnv *env, jobject intent, jclass intentClass, const char *key,
                          const std::string &value) {
        jmethodID putStringExtra = env->GetMethodID(
                intentClass,
                "putExtra",
                "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;"
        );
        if (putStringExtra == nullptr) {
            return;
        }
        jstring keyString = env->NewStringUTF(key);
        jstring valueString = env->NewStringUTF(value.c_str());
        env->CallObjectMethod(intent, putStringExtra, keyString, valueString);
        env->DeleteLocalRef(keyString);
        env->DeleteLocalRef(valueString);
    }

    void attach_preload_extras(
            JNIEnv *env,
            jobject intent,
            jclass intentClass,
            const duckdetector::preload::EarlyMountPreloadResult &result
    ) {
        put_boolean_extra(env, intent, intentClass, "early_detection_has_run", true);
        put_boolean_extra(env, intent, intentClass, "early_detection_detected", result.detected);
        put_string_extra(env, intent, intentClass, "early_detection_method",
                         result.detectionMethod);
        put_string_extra(env, intent, intentClass, "early_detection_details", result.details);
        put_boolean_extra(
                env,
                intent,
                intentClass,
                "early_preload_context_valid",
                duckdetector::preload::is_preload_context_valid()
        );
        put_boolean_extra(env, intent, intentClass, "early_futile_hide", result.futileHideDetected);
        put_boolean_extra(env, intent, intentClass, "early_mnt_strings", result.mntStringsDetected);
        put_boolean_extra(env, intent, intentClass, "early_mount_id_gap",
                          result.mountIdGapDetected);
        put_boolean_extra(env, intent, intentClass, "early_minor_dev_gap",
                          result.minorDevGapDetected);
        put_boolean_extra(env, intent, intentClass, "early_peer_group_gap",
                          result.peerGroupGapDetected);
        put_long_extra(env, intent, intentClass, "early_ns_mnt_ctime_delta_ns",
                       result.nsMntCtimeDeltaNs);
        put_long_extra(env, intent, intentClass, "early_mountinfo_ctime_delta_ns",
                       result.mountInfoCtimeDeltaNs);
        put_string_extra(env, intent, intentClass, "early_mnt_strings_source",
                         result.mntStringsSource);
        put_string_extra(env, intent, intentClass, "early_mnt_strings_target",
                         result.mntStringsTarget);
        put_string_extra(env, intent, intentClass, "early_mnt_strings_fs", result.mntStringsFs);
    }

    void attach_virtualization_preload_extras(
            JNIEnv *env,
            jobject intent,
            jclass intentClass,
            const duckdetector::preload::virtualization::EarlyVirtualizationResult &result
    ) {
        put_boolean_extra(env, intent, intentClass, "early_virtualization_has_run", true);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_detected",
                          result.detected);
        put_string_extra(env, intent, intentClass, "early_virtualization_method",
                         result.detectionMethod);
        put_string_extra(env, intent, intentClass, "early_virtualization_details", result.details);
        put_boolean_extra(
                env,
                intent,
                intentClass,
                "early_virtualization_context_valid",
                duckdetector::preload::virtualization::is_preload_context_valid()
        );
        put_boolean_extra(env, intent, intentClass, "early_virtualization_qemu_property",
                          result.qemuPropertyDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_emulator_hardware",
                          result.emulatorHardwareDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_device_node",
                          result.deviceNodeDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_avf_runtime",
                          result.avfRuntimeDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_authfs_runtime",
                          result.authfsRuntimeDetected);
        put_boolean_extra(env, intent, intentClass, "early_virtualization_native_bridge",
                          result.nativeBridgeDetected);
        put_string_extra(env, intent, intentClass, "early_virtualization_mount_namespace_inode",
                         result.mountNamespaceInode);
        put_string_extra(env, intent, intentClass, "early_virtualization_apex_mount_key",
                         result.apexMountKey);
        put_string_extra(env, intent, intentClass, "early_virtualization_system_mount_key",
                         result.systemMountKey);
        put_string_extra(env, intent, intentClass, "early_virtualization_vendor_mount_key",
                         result.vendorMountKey);
    }

    void start_main_activity_and_finish(JNIEnv *env, jobject activity) {
        const std::int64_t nowNs = monotonic_now_ns();
        if (g_lastHandoffNs != 0 && (nowNs - g_lastHandoffNs) < kDuplicateLaunchWindowNs) {
            finish_activity(env, activity);
            return;
        }

        const auto *stored = duckdetector::preload::get_stored_result();
        const duckdetector::preload::EarlyMountPreloadResult emptyResult{};
        const auto &result = stored != nullptr ? *stored : emptyResult;
        const auto *virtualizationStored = duckdetector::preload::virtualization::get_stored_result();
        const duckdetector::preload::virtualization::EarlyVirtualizationResult emptyVirtualizationResult{};
        const auto &virtualizationResult = virtualizationStored != nullptr
                                           ? *virtualizationStored
                                           : emptyVirtualizationResult;

        jclass activityClass = env->GetObjectClass(activity);
        if (activityClass == nullptr) {
            LOGE("Failed to resolve NativeActivity class");
            return;
        }

        jmethodID getPackageName = env->GetMethodID(activityClass, "getPackageName",
                                                    "()Ljava/lang/String;");
        jmethodID startActivity = env->GetMethodID(activityClass, "startActivity",
                                                   "(Landroid/content/Intent;)V");
        jmethodID finish = env->GetMethodID(activityClass, "finish", "()V");
        if (getPackageName == nullptr || startActivity == nullptr || finish == nullptr) {
            LOGE("Failed to resolve NativeActivity methods");
            env->DeleteLocalRef(activityClass);
            return;
        }

        jstring packageName = static_cast<jstring>(env->CallObjectMethod(activity, getPackageName));
        if (packageName == nullptr) {
            LOGE("Failed to read package name");
            env->DeleteLocalRef(activityClass);
            return;
        }

        const char *packageChars = env->GetStringUTFChars(packageName, nullptr);
        const std::string packageNameString(packageChars == nullptr ? "" : packageChars);
        if (packageChars != nullptr) {
            env->ReleaseStringUTFChars(packageName, packageChars);
        }

        jclass intentClass = env->FindClass("android/content/Intent");
        jclass componentNameClass = env->FindClass("android/content/ComponentName");
        if (intentClass == nullptr || componentNameClass == nullptr) {
            LOGE("Failed to resolve Intent/ComponentName");
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(activityClass);
            return;
        }

        jmethodID intentInit = env->GetMethodID(intentClass, "<init>", "()V");
        jmethodID addFlags = env->GetMethodID(intentClass, "addFlags",
                                              "(I)Landroid/content/Intent;");
        jmethodID setComponent = env->GetMethodID(
                intentClass,
                "setComponent",
                "(Landroid/content/ComponentName;)Landroid/content/Intent;"
        );
        jmethodID componentInit = env->GetMethodID(
                componentNameClass,
                "<init>",
                "(Ljava/lang/String;Ljava/lang/String;)V"
        );
        if (intentInit == nullptr || addFlags == nullptr || setComponent == nullptr ||
            componentInit == nullptr) {
            LOGE("Failed to resolve Intent/ComponentName methods");
            env->DeleteLocalRef(componentNameClass);
            env->DeleteLocalRef(intentClass);
            env->DeleteLocalRef(packageName);
            env->DeleteLocalRef(activityClass);
            return;
        }

        jobject intent = env->NewObject(intentClass, intentInit);
        const std::string mainActivityClassName = packageNameString + ".MainActivity";
        jstring packageString = env->NewStringUTF(packageNameString.c_str());
        jstring classString = env->NewStringUTF(mainActivityClassName.c_str());
        jobject component = env->NewObject(componentNameClass, componentInit, packageString,
                                           classString);

        env->CallObjectMethod(intent, setComponent, component);
        constexpr int FLAG_ACTIVITY_NEW_TASK = 0x10000000;
        constexpr int FLAG_ACTIVITY_CLEAR_TOP = 0x04000000;
        constexpr int FLAG_ACTIVITY_SINGLE_TOP = 0x20000000;
        env->CallObjectMethod(
                intent,
                addFlags,
                FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TOP | FLAG_ACTIVITY_SINGLE_TOP
        );

        attach_preload_extras(env, intent, intentClass, result);
        attach_virtualization_preload_extras(env, intent, intentClass, virtualizationResult);

        env->CallVoidMethod(activity, startActivity, intent);
        env->CallVoidMethod(activity, finish);
        g_lastHandoffNs = nowNs;

        env->DeleteLocalRef(component);
        env->DeleteLocalRef(classString);
        env->DeleteLocalRef(packageString);
        env->DeleteLocalRef(intent);
        env->DeleteLocalRef(componentNameClass);
        env->DeleteLocalRef(intentClass);
        env->DeleteLocalRef(packageName);
        env->DeleteLocalRef(activityClass);
    }

    void on_destroy(ANativeActivity *activity) {
        (void) activity;
    }

    void on_start(ANativeActivity *activity) {
        (void) activity;
    }

    void on_resume(ANativeActivity *activity) {
        (void) activity;
    }

    void on_pause(ANativeActivity *activity) {
        (void) activity;
    }

    void on_stop(ANativeActivity *activity) {
        (void) activity;
    }

    void on_window_focus_changed(ANativeActivity *activity, int focused) {
        (void) activity;
        (void) focused;
    }

}  // namespace

extern "C" __attribute__((visibility("default")))
void native_activity_preload(JNIEnv *env, jobject activity) {
    if (!duckdetector::preload::has_early_detection_run()) {
        duckdetector::preload::run_early_detection();
    }
    if (!duckdetector::preload::virtualization::has_early_detection_run()) {
        duckdetector::preload::virtualization::run_early_detection();
    }
    start_main_activity_and_finish(env, activity);
}

extern "C" __attribute__((visibility("default")))
void ANativeActivity_onCreate(ANativeActivity *activity, void *savedState, size_t savedStateSize) {
    (void) savedState;
    (void) savedStateSize;

    if (activity != nullptr && activity->callbacks != nullptr) {
        activity->callbacks->onDestroy = on_destroy;
        activity->callbacks->onStart = on_start;
        activity->callbacks->onResume = on_resume;
        activity->callbacks->onPause = on_pause;
        activity->callbacks->onStop = on_stop;
        activity->callbacks->onWindowFocusChanged = on_window_focus_changed;
    }

    if (!duckdetector::preload::has_early_detection_run()) {
        duckdetector::preload::run_early_detection();
    }
    if (!duckdetector::preload::virtualization::has_early_detection_run()) {
        duckdetector::preload::virtualization::run_early_detection();
    }

    JavaVM *vm = activity->vm;
    JNIEnv *env = nullptr;
    bool attached = false;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
            attached = true;
        }
    }

    if (env == nullptr) {
        LOGE("Failed to acquire JNIEnv for NativeActivity handoff");
        return;
    }

    start_main_activity_and_finish(env, activity->clazz);
    if (attached) {
        vm->DetachCurrentThread();
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeHasEarlyDetectionRun(
        JNIEnv *,
        jobject
) {
    return duckdetector::preload::has_early_detection_run();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeIsPreloadContextValid(
        JNIEnv *,
        jobject
) {
    return duckdetector::preload::is_preload_context_valid();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeWasDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->detected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeWasFutileHideDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->futileHideDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeWasMinorDevGapDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->minorDevGapDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeWasMountIdGapDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->mountIdGapDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeWasMntStringsDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->mntStringsDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeWasPeerGroupGapDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? result->peerGroupGapDetected : false;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeGetDetectionMethod(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->detectionMethod.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeGetDetails(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->details.c_str() : "");
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeGetFindings(
        JNIEnv *env,
        jobject
) {
    jclass stringClass = env->FindClass("java/lang/String");
    const auto *result = duckdetector::preload::get_stored_result();
    if (result == nullptr || result->findings.empty()) {
        return env->NewObjectArray(0, stringClass, nullptr);
    }

    jobjectArray array = env->NewObjectArray(
            static_cast<jsize>(result->findings.size()),
            stringClass,
            nullptr
    );
    for (std::size_t index = 0; index < result->findings.size(); ++index) {
        jstring item = env->NewStringUTF(result->findings[index].c_str());
        env->SetObjectArrayElement(array, static_cast<jsize>(index), item);
        env->DeleteLocalRef(item);
    }
    return array;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeGetNsMntCtimeDeltaNs(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? static_cast<jlong>(result->nsMntCtimeDeltaNs) : 0;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeGetMountInfoCtimeDeltaNs(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return result != nullptr ? static_cast<jlong>(result->mountInfoCtimeDeltaNs) : 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeGetMntStringsSource(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->mntStringsSource.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeGetMntStringsTarget(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->mntStringsTarget.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeGetMntStringsFs(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->mntStringsFs.c_str() : "");
}

extern "C" JNIEXPORT void JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyMountPreloadBridge_nativeReset(
        JNIEnv *,
        jobject
) {
    duckdetector::preload::reset_early_detection();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeHasEarlyDetectionRun(
        JNIEnv *,
        jobject
) {
    return duckdetector::preload::virtualization::has_early_detection_run();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeIsPreloadContextValid(
        JNIEnv *,
        jobject
) {
    return duckdetector::preload::virtualization::is_preload_context_valid();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeWasDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->detected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeWasQemuPropertyDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->qemuPropertyDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeWasEmulatorHardwareDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->emulatorHardwareDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeWasDeviceNodeDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->deviceNodeDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeWasAvfRuntimeDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->avfRuntimeDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeWasAuthfsRuntimeDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->authfsRuntimeDetected : false;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeWasNativeBridgeDetected(
        JNIEnv *,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return result != nullptr ? result->nativeBridgeDetected : false;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeGetDetectionMethod(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->detectionMethod.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeGetDetails(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->details.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeGetMountNamespaceInode(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->mountNamespaceInode.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeGetApexMountKey(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->apexMountKey.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeGetSystemMountKey(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->systemMountKey.c_str() : "");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeGetVendorMountKey(
        JNIEnv *env,
        jobject
) {
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    return env->NewStringUTF(result != nullptr ? result->vendorMountKey.c_str() : "");
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeGetFindings(
        JNIEnv *env,
        jobject
) {
    jclass stringClass = env->FindClass("java/lang/String");
    const auto *result = duckdetector::preload::virtualization::get_stored_result();
    if (result == nullptr || result->findings.empty()) {
        return env->NewObjectArray(0, stringClass, nullptr);
    }

    jobjectArray array = env->NewObjectArray(
            static_cast<jsize>(result->findings.size()),
            stringClass,
            nullptr
    );
    for (std::size_t index = 0; index < result->findings.size(); ++index) {
        jstring item = env->NewStringUTF(result->findings[index].c_str());
        env->SetObjectArrayElement(array, static_cast<jsize>(index), item);
        env->DeleteLocalRef(item);
    }
    return array;
}

extern "C" JNIEXPORT void JNICALL
Java_com_eltavine_duckdetector_core_startup_preload_EarlyVirtualizationPreloadBridge_nativeReset(
        JNIEnv *,
        jobject
) {
    duckdetector::preload::virtualization::reset_early_detection();
}
