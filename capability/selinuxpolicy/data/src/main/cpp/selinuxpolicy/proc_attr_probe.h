// SPDX-License-Identifier: Apache-2.0
#ifndef DUCKDETECTOR_SELINUX_PROC_ATTR_PROBE_H
#define DUCKDETECTOR_SELINUX_PROC_ATTR_PROBE_H

#include "common/disposable_child.h"
#include <array>
#include <cstdint>

namespace duckdetector::selinux::proc_attr {
    constexpr unsigned kRounds = 2;
    constexpr unsigned kTargets = 9;
    constexpr char kCarrier[] = "u:r:app_zygote:s0";
    constexpr char kMalformed[] = "duckdetector-invalid-context";
    struct Target { const char *label; const char *context; };
    inline constexpr std::array<Target, kTargets> targets{{
        {"KernelSU", "u:r:ksu:s0"}, {"KernelSU file", "u:object_r:ksu_file:s0"},
        {"Magisk", "u:r:magisk:s0"}, {"Magisk file", "u:object_r:magisk_file:s0"},
        {"LSPosed file", "u:object_r:lsposed_file:s0"}, {"DroidSpaces daemon", "u:r:droidspacesd:s0"},
        {"MSD app", "u:r:msd_app:s0"}, {"MSD daemon", "u:r:msd_daemon:s0"},
        {"Xposed data", "u:object_r:xposed_data:s0"},
    }};
    enum class State { kUnavailable, kUnsupported, kPermissionLimited, kInconclusive, kComplete };
    enum class Step { kCarrier, kControlsBefore, kTargets, kControlsAfter, kFinished };
    struct WriteResult {
        int open_error = 0;
        int write_error = 0;
        int64_t bytes = -2; // -2: not issued; -1: write failed; >=0: actual byte count.
    };
    struct Controls { WriteResult malformed; WriteResult stock; };
    struct Report {
        State state = State::kUnavailable;
        Step step = Step::kCarrier;
        int error = 0;
        unsigned completed_rounds = 0;
        bool identity_changed = false;
        std::array<Controls, kRounds * 2> controls{};
        std::array<std::array<WriteResult, kTargets>, kRounds> writes{};
    };
    struct Result {
        Report report;
        common::ChildOutcome child;
    };
    // These operations target this probe's current thread, including when called from ART workers.
    int read_identity(char *context, unsigned capacity);
    WriteResult write_current(const char *context);
    Result collect();
}
#endif
