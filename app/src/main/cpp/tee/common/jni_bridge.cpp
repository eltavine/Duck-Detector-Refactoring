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

#include <cstdint>
#include <string>
#include <vector>

#include "tee/common/result_codec.h"
#include "tee/common/syscall_facade.h"
#include "tee/der/der_probe.h"
#include "tee/keystore/environment_probe.h"
#include "tee/trickystore/trickystore_probe.h"

namespace {

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_tee_data_native_TeeNativeBridge_nativeCollectEnvironment(
        JNIEnv *env,
        jobject) {
    const auto snapshot = ducktee::keystore::collect_environment();
    ducktee::common::ResultCodec codec;
    codec.put_bool("TRACING", snapshot.tracing_detected);
    codec.put_int("PAGE_SIZE", snapshot.page_size);
    codec.put("TIMING", snapshot.timing_summary);
    codec.put_many("MAPPING", snapshot.suspicious_mappings);
    return to_jstring(env, codec.str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_tee_data_native_TeeNativeBridge_nativeInspectTrickyStore(
        JNIEnv *env,
        jobject) {
    const auto snapshot = ducktee::trickystore::inspect_process();
    ducktee::common::ResultCodec codec;
    codec.put_bool("DETECTED", snapshot.detected);
    codec.put_bool("GOT_HOOK", snapshot.got_hook_detected);
    codec.put_bool("SYSCALL_MISMATCH", snapshot.syscall_mismatch_detected);
    codec.put_bool("INLINE_HOOK", snapshot.inline_hook_detected);
    codec.put_bool("HONEYPOT", snapshot.honeypot_detected);
    codec.put_int("RUNS", snapshot.honeypot_run_count);
    codec.put_int("SUSPICIOUS_RUNS", snapshot.honeypot_suspicious_run_count);
    codec.put_int("MEDIAN_GAP_NS", static_cast<long>(snapshot.honeypot_median_gap_ns));
    codec.put_int("GAP_MAD_NS", static_cast<long>(snapshot.honeypot_gap_mad_ns));
    codec.put_int("MEDIAN_NOISE_NS", static_cast<long>(snapshot.honeypot_median_noise_floor_ns));
    codec.put_int("MEDIAN_RATIO_PERCENT", snapshot.honeypot_median_ratio_percent);
    codec.put("TIMER_SOURCE", snapshot.timer_source);
    codec.put("TIMER_FALLBACK", snapshot.timer_fallback_reason);
    codec.put("AFFINITY", snapshot.affinity_status);
    codec.put("DETAILS", snapshot.details);
    codec.put_many("METHOD", snapshot.methods);
    return to_jstring(env, codec.str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_tee_data_native_TeeNativeBridge_nativeInspectLeafDer(
        JNIEnv *env,
        jobject,
        jbyteArray leaf_der) {
    if (leaf_der == nullptr) {
        return to_jstring(env, "PRIMARY=0\nSECONDARY=0\nDETAILS=leaf der missing\n");
    }

    const jsize size = env->GetArrayLength(leaf_der);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    env->GetByteArrayRegion(
            leaf_der,
            0,
            size,
            reinterpret_cast<jbyte *>(bytes.data()));

    const auto snapshot = ducktee::der::scan_leaf_der(bytes);
    ducktee::common::ResultCodec codec;
    codec.put_bool("PRIMARY", snapshot.primary_detected);
    codec.put_bool("SECONDARY", snapshot.secondary_detected);
    codec.put_many("FINDING", snapshot.findings);
    return to_jstring(env, codec.str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_features_tee_data_native_TeeRegisterTimerNativeBridge_nativeIsRegisterTimerAvailable(
        JNIEnv *,
        jobject) {
    std::uint64_t value_ns = 0;
    return ducktee::common::register_timer_time_ns(&value_ns) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_eltavine_duckdetector_features_tee_data_native_TeeRegisterTimerNativeBridge_nativeReadRegisterTimerNs(
        JNIEnv *,
        jobject) {
    std::uint64_t value_ns = 0;
    if (!ducktee::common::register_timer_time_ns(&value_ns)) {
        return -1;
    }
    return static_cast<jlong>(value_ns);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eltavine_duckdetector_features_tee_data_native_TeeRegisterTimerNativeBridge_nativeBindCurrentThreadToCpu0(
        JNIEnv *,
        jobject) {
    return ducktee::common::bind_current_thread_to_cpu0() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_tee_data_native_TeeRegisterTimerNativeBridge_nativeSelectPreferredTimer(
        JNIEnv *env,
        jobject,
        jboolean request_cpu0_affinity) {
    ducktee::common::LocalTimerSelection selection;
    ducktee::common::select_preferred_local_timer(request_cpu0_affinity == JNI_TRUE, &selection);

    ducktee::common::ResultCodec codec;
    codec.put_bool(
            "REGISTER_TIMER_AVAILABLE",
            selection.kind == ducktee::common::LocalTimerKind::Arm64Cntvct
    );
    codec.put("TIMER_SOURCE", selection.source_label);
    codec.put("FALLBACK_REASON", selection.fallback_reason);
    codec.put("AFFINITY", selection.affinity_status);
    return to_jstring(env, codec.str());
}
