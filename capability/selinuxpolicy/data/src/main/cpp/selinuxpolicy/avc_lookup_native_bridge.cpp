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
            << "\nPID=" << report.pid
            << "\nCPU_MIGRATIONS=" << report.cpu_migrations
            << "\nTIMING_MEDIANS_VALID=" << (report.timing_medians_available ? 1 : 0)
            << "\nA_SLOWER=" << report.a_slower
            << "\nPOSITIVE_BLOCKS=" << report.positive_blocks
            << "\nNEGATIVE_BLOCKS=" << report.negative_blocks
            << "\nZERO_BLOCKS=" << report.zero_blocks
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

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxAvcLookupProbe_nativeCollectParentTiming(
        JNIEnv *env, jobject) {
    std::ostringstream out;
    try {
        // Validate reachability in an isolated child first. The full 33k-write AVC
        // workload must NOT precede this parent measurement: it changes the CPU
        // scheduling/cache state and flips the sign on the physical regression device.
        ParentTiming parent;
        const int preflight_error = verify_parent_timing_preflight();
        if (preflight_error) {
            parent.protocol = 1;
            parent.error = preflight_error;
        } else {
            parent = collect_parent_timing();
        }
        out << "PARENT_ATTEMPTED=1\nPARENT_COMPLETE=" << (parent.complete ? 1 : 0)
            << "\nPARENT_PROTOCOL=" << parent.protocol
            << "\nPARENT_POSITIVE_BLOCKS=" << parent.positive_blocks
            << "\nPARENT_NEGATIVE_BLOCKS=" << parent.negative_blocks
            << "\nPARENT_ZERO_BLOCKS=" << parent.zero_blocks
            << "\nPARENT_ERROR=" << parent.error << "\nPARENT_PID=" << parent.pid
            << "\nPARENT_CPU=" << parent.cpu << "\nPARENT_PAIRS=" << parent.pairs
            << "\nPARENT_MIGRATIONS=" << parent.migrations << "\nPARENT_A_SLOWER=" << parent.a_slower
            << "\nPARENT_MEDIANS_VALID=" << (parent.medians_available ? 1 : 0)
            << "\nPARENT_MEDIAN_A_NS=" << parent.median_a_ns
            << "\nPARENT_MEDIAN_B_NS=" << parent.median_b_ns
            << "\nPARENT_MEDIAN_DELTA_NS=" << parent.median_delta_ns << '\n';
    } catch (...) { out << "PARENT_ATTEMPTED=0\nPARENT_ERROR=5\n"; }
    return env->NewStringUTF(out.str().c_str());
}
