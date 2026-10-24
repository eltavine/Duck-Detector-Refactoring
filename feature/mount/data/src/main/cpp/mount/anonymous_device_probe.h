// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <vector>

namespace duckdetector::mount::detail {
    struct MountInfoEntry;

    enum class AnonymousDeviceState {
        Unavailable,
        Unsupported,
        Inconclusive,
        Partial,
        Observed,
        NoGaps,
    };

    struct AnonymousDeviceObservation {
        AnonymousDeviceState state = AnonymousDeviceState::Unavailable;
        std::string detail;
    };

    AnonymousDeviceObservation observe_anonymous_devices(
            const std::vector<MountInfoEntry> &entries,
            bool completeCapture,
            const std::string &externalStorageRoot
    );

    const char *anonymous_device_state_key(AnonymousDeviceState state);
}
