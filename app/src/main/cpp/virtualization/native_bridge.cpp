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

#include "virtualization/honeypot_traps.h"
#include "virtualization/snapshot_builder.h"

namespace {

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_virtualization_data_native_VirtualizationNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject
) {
    return to_jstring(env, duckdetector::virtualization::encode_snapshot(
            duckdetector::virtualization::collect_snapshot()));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_virtualization_data_native_VirtualizationNativeBridge_nativeRunTimingTrap(
        JNIEnv *env,
        jobject
) {
    return to_jstring(env, duckdetector::virtualization::encode_trap(
            duckdetector::virtualization::run_timing_trap()));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_virtualization_data_native_VirtualizationNativeBridge_nativeRunSyscallParityTrap(
        JNIEnv *env,
        jobject
) {
    return to_jstring(env, duckdetector::virtualization::encode_trap(
            duckdetector::virtualization::run_syscall_parity_trap()));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_virtualization_data_native_VirtualizationNativeBridge_nativeRunAsmCounterTrap(
        JNIEnv *env,
        jobject
) {
    return to_jstring(env, duckdetector::virtualization::encode_trap(
            duckdetector::virtualization::run_asm_counter_trap()));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_virtualization_data_native_VirtualizationNativeBridge_nativeRunAsmRawSyscallTrap(
        JNIEnv *env,
        jobject
) {
    return to_jstring(env, duckdetector::virtualization::encode_trap(
            duckdetector::virtualization::run_asm_raw_syscall_trap()));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_virtualization_data_native_VirtualizationNativeBridge_nativeRunSacrificialSyscallPack(
        JNIEnv *env,
        jobject
) {
    return to_jstring(env, duckdetector::virtualization::run_sacrificial_syscall_pack());
}
