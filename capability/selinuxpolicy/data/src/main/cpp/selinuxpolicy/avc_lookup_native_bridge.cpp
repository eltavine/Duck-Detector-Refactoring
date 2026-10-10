// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/avc_lookup_probe.h"
#include <jni.h>
#include <sstream>
#include <string>

namespace {
    using namespace duckdetector::selinux::avc_lookup;
    using duckdetector::common::ChildEnd;

    const char *state_name(const State state) {
        switch (state) {
            case State::kUnavailable: return "UNAVAILABLE";
            case State::kUnsupported: return "UNSUPPORTED";
            case State::kPermissionLimited: return "PERMISSION_LIMITED";
            case State::kTimingOnly: return "TIMING_ONLY";
            case State::kCollected: return "COLLECTED";
            case State::kInconclusive: return "INCONCLUSIVE";
        }
        return "INCONCLUSIVE";
    }

    const char *step_name(const Step step) {
        switch (step) {
            case Step::kCarrier: return "CARRIER";
            case Step::kEnforce: return "ENFORCE";
            case Step::kOpen: return "OPEN";
            case Step::kControls: return "CONTROLS";
            case Step::kTiming: return "TIMING";
            case Step::kAffinity: return "AFFINITY";
            case Step::kCpuMap: return "CPU_MAP";
            case Step::kStats: return "STATS";
            case Step::kCounting: return "COUNTING";
            case Step::kIdentity: return "IDENTITY";
            case Step::kFinished: return "FINISHED";
        }
        return "CARRIER";
    }

    const char *payload_name(const Payload payload) {
        switch (payload) {
            case Payload::kNone: return "NONE";
            case Payload::kA: return "A";
            case Payload::kB: return "B";
        }
        return "NONE";
    }

    const char *child_end_name(const ChildEnd end) {
        switch (end) {
            case ChildEnd::kNotStarted: return "NOT_STARTED";
            case ChildEnd::kSetupFailed: return "SETUP_FAILED";
            case ChildEnd::kExited: return "EXITED";
            case ChildEnd::kSignaled: return "SIGNALED";
            case ChildEnd::kSeccompTrapped: return "SECCOMP_TRAPPED";
            case ChildEnd::kTimedOut: return "TIMED_OUT";
            case ChildEnd::kNotReaped: return "NOT_REAPED";
            case ChildEnd::kWaitFailed: return "WAIT_FAILED";
        }
        return "WAIT_FAILED";
    }

    std::string join(const std::array<uint32_t, kRounds> &values) {
        std::string joined;
        for (unsigned index = 0; index < values.size(); ++index) {
            if (index) joined += ',';
            joined += std::to_string(values[index]);
        }
        return joined;
    }

    std::string encode(const Result &result) {
        const auto &report = result.report;
        std::ostringstream out;
        out << "SCHEMA=1\nSTATE=" << state_name(report.state) << "\nSTEP=" << step_name(report.step)
            << "\nERRNO=" << report.error << "\nUNEXPECTED_PAYLOAD=" << payload_name(report.unexpected)
            << "\nUNEXPECTED_RETURNED=" << report.unexpected_bytes
            << "\nIDENTITY_CHANGED=" << (report.identity_changed ? 1 : 0)
            << "\nCPU=" << report.cpu << "\nCPU_ROW=" << report.cpu_row << "\nCPU_ROWS=" << report.cpu_rows
            << "\nPOSSIBLE_CPUS=" << report.possible_cpus << "\nPAIRS=" << report.pairs
            << "\nROUNDS=" << report.rounds << "\nWRITES=" << kWrites
            << "\nBATCH_A=" << join(report.batch_a) << "\nBATCH_B=" << join(report.batch_b)
            << "\nMEDIAN_A_NS=" << report.median_a_ns << "\nMEDIAN_B_NS=" << report.median_b_ns
            << "\nMEDIAN_DELTA_NS=" << report.median_delta_ns
            << "\nCHILD_END=" << child_end_name(result.child.end) << "\nCHILD_EXIT=" << result.child.exit_status
            << "\nCHILD_SIGNAL=" << result.child.signal << "\nCHILD_ERRNO=" << result.child.error << '\n';
        return out.str();
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxAvcLookupProbe_nativeCollectAvcLookup(
        JNIEnv *env, jobject) {
    std::string payload;
    try { payload = encode(collect()); }
    catch (...) { payload = "SCHEMA=1\nSTATE=UNAVAILABLE\nFAILURE_REASON=Native AVC lookup collection failed.\n"; }
    return env->NewStringUTF(payload.c_str());
}
