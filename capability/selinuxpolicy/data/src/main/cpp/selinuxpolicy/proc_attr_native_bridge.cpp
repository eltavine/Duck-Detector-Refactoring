// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/proc_attr_probe.h"
#include "common/payload_codec.h"
#include <jni.h>
#include <cerrno>
#include <sstream>
#include <string>

namespace {
    using namespace duckdetector::selinux::proc_attr;
    const char *state_name(const State state) {
        switch (state) {
            case State::kComplete: return "COMPLETE";
            case State::kUnsupported: return "UNSUPPORTED";
            case State::kPermissionLimited: return "PERMISSION_LIMITED";
            case State::kUnavailable: return "UNAVAILABLE";
            case State::kInconclusive: return "INCONCLUSIVE";
        }
        return "INCONCLUSIVE";
    }
    std::string describe(const WriteResult &write) {
        return "open_errno=" + std::to_string(write.open_error) +
               ", write_errno=" + std::to_string(write.write_error) + ", returned=" + std::to_string(write.bytes);
    }
    bool denied(const WriteResult &result, const int error) {
        return result.open_error == 0 && result.bytes == -1 && result.write_error == error;
    }
    std::string encode(const Result &result) {
        const auto &report = result.report;
        const auto escaped = duckdetector::common::escape_payload_value;
        std::ostringstream out;
        out << "SCHEMA=1\n";
        std::string detail = std::string("state=") + state_name(report.state) +
            "; step=" + std::to_string(static_cast<int>(report.step)) + "; errno=" + std::to_string(report.error) +
            "; rounds=" + std::to_string(report.completed_rounds) +
            "; identity_changed=" + (report.identity_changed ? "yes" : "no") +
            "; child_end=" + std::to_string(static_cast<int>(result.child.end)) +
            "; child_errno=" + std::to_string(result.child.error) +
            "; exit_status=" + std::to_string(result.child.exit_status) +
            "; signal=" + std::to_string(result.child.signal);
        for (unsigned i = 0; i < report.controls.size(); ++i) {
            detail += "; control" + std::to_string(i) + " malformed(" + describe(report.controls[i].malformed) +
                      ") stock(" + describe(report.controls[i].stock) + ")";
        }
        out << "RESULT=Controls\t\t" << (report.state == State::kComplete ? "CONTROLS_PASSED" : state_name(report.state))
            << '\t' << escaped(detail) << '\n';
        for (unsigned index = 0; index < kTargets; ++index) {
            const auto &first = report.writes[0][index];
            const auto &second = report.writes[1][index];
            const char *outcome = "INCONCLUSIVE";
            if (report.state == State::kComplete && denied(first, EACCES) && denied(second, EACCES))
                outcome = "CONTEXT_RECOGNIZED";
            else if (report.state == State::kComplete && denied(first, EINVAL) && denied(second, EINVAL))
                outcome = "NORMAL_EINVAL";
            out << "RESULT=" << escaped(targets[index].label) << '\t' << escaped(targets[index].context) << '\t'
                << outcome << '\t' << escaped("round0(" + describe(first) + "); round1(" + describe(second) +
                   "); state=" + state_name(report.state)) << '\n';
        }
        return out.str();
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxProcAttrCurrentProbe_nativeCollectProcAttr(
        JNIEnv *env, jobject) {
    std::string payload;
    try { payload = encode(duckdetector::selinux::proc_attr::collect()); }
    catch (...) { payload = "SCHEMA=1\nRESULT=Controls\t\tUNAVAILABLE\tNative collection failed\n"; }
    return env->NewStringUTF(payload.c_str());
}
