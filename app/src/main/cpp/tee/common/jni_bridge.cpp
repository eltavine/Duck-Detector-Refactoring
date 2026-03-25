#include <jni.h>

#include <string>
#include <vector>

#include "tee/common/result_codec.h"
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
