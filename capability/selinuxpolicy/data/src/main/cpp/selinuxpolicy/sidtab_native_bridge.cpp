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

#include "selinuxpolicy/sidtab_probe.h"
#include "common/payload_codec.h"

#include <jni.h>
#include <exception>
#include <sstream>
#include <string>

namespace {
    using namespace duckdetector::selinux::sidtab;
    const char *state_name(const State state) {
        switch (state) {
            case State::kNotCollected: return "NOT_COLLECTED";
            case State::kComplete: return "COMPLETE";
            case State::kUnsupported: return "UNSUPPORTED";
            case State::kPermissionLimited: return "PERMISSION_LIMITED";
            case State::kUnavailable: return "UNAVAILABLE";
            case State::kInconclusive: return "INCONCLUSIVE";
        }
        return "INCONCLUSIVE";
    }
    const char *step_name(const Step step) {
        switch (step) {
            case Step::kSetup: return "SETUP";
            case Step::kCarrier: return "CARRIER";
            case Step::kControls: return "CONTROLS";
            case Step::kContext: return "CONTEXT";
            case Step::kAttrCurrent: return "ATTR_CURRENT";
            case Step::kRepeat: return "REPEAT";
            case Step::kFinished: return "FINISHED";
        }
        return "SETUP";
    }
    std::string encode(const Result &result) {
        std::ostringstream out;
        const auto &report = result.report;
        const auto escaped = duckdetector::common::escape_payload_value;
        out << "SCHEMA=1\nSTATE=" << state_name(report.state) << '\n';
        out << "ATTEMPTED=" << (result.attempted ? '1' : '0') << '\n';
        out << "STEP=" << step_name(report.step) << "\nERRNO=" << report.error << '\n';
        out << "COMPLETED_ROUNDS=" << report.completed_rounds << '\n';
        out << "CANONICAL_MISMATCH=" << (report.canonical_mismatch ? '1' : '0') << '\n';
        out << "IDENTITY_CHANGED=" << (report.identity_changed ? '1' : '0') << '\n';
        out << "UID=" << result.uid << "\nPID=" << result.pid << '\n';
        out << "CAPTURED_UPTIME_MS=" << result.captured_uptime_ms << '\n';
        out << "CARRIER=" << escaped(report.carrier) << '\n';
        out << "KERNEL_RELEASE=" << escaped(result.kernel_release) << '\n';
        out << "CHILD_END=" << escaped(result.child_end) << "\nSIGNAL=" << result.signal << '\n';
        for (unsigned index = 0; index < kRounds; ++index) {
            const auto &round = report.rounds[index];
            const std::string prefix = "R" + std::to_string(index) + "_";
            out << prefix << "BEFORE_CONTROLS=" << round.before_controls << '\n';
            out << prefix << "BEFORE=" << round.before << '\n';
            out << prefix << "AFTER_CONTEXT=" << round.after_context << '\n';
            out << prefix << "AFTER_ATTR=" << round.after_attr << '\n';
            out << prefix << "AFTER_REPEAT=" << round.after_repeat << '\n';
            out << prefix << "IDLE_END=" << round.idle_end << '\n';
            out << prefix << "POSITIVE_ERRNO=" << round.positive_error << '\n';
            out << prefix << "NEGATIVE_ERRNO=" << round.negative_error << '\n';
            for (unsigned sample_index = 0; sample_index < kSamples; ++sample_index) {
                const auto &sample = round.samples[sample_index];
                const auto key = prefix + "S" + std::to_string(sample_index) + "_";
                out << key << "CONTEXT=" << escaped(sample.context) << '\n';
                out << key << "CONTEXT_ERRNO=" << sample.context_error << '\n';
                out << key << "ATTR_ERRNO=" << sample.attr_error << '\n';
                out << key << "REPEAT_ERRNO=" << sample.repeat_error << '\n';
            }
        }
        return out.str();
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxSidtabProbe_nativeCollectSidtab(
        JNIEnv *env, jobject) {
    std::string payload;
    try { payload = encode(duckdetector::selinux::sidtab::collect()); }
    catch (...) { payload = "SCHEMA=1\nSTATE=UNAVAILABLE\nATTEMPTED=0\nSTEP=SETUP\n"; }
    return env->NewStringUTF(payload.c_str());
}
