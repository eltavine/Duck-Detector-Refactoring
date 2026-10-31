#include <jni.h>
#include <vector>
#include "nativeroot/probes/ksu_wrapper_leak_probe.h"

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_KernelSuWrapperLeakNativeBridge_nativeCollect(
        JNIEnv *env, jobject) {
    const auto sample = duckdetector::nativeroot::collect_wrapper_leak();
    std::vector<jlong> payload{1, static_cast<jlong>(sample.stage), sample.error,
                               sample.completed, sample.reopens, sample.count};
    for (int i = 0; i < sample.count; ++i) {
        payload.push_back(sample.points[i].median);
        payload.push_back(sample.points[i].spread);
    }
    jlongArray output = env->NewLongArray(static_cast<jsize>(payload.size()));
    if (output) env->SetLongArrayRegion(output, 0, static_cast<jsize>(payload.size()), payload.data());
    return output;
}
