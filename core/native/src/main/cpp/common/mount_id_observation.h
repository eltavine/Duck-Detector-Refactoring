// SPDX-License-Identifier: Apache-2.0
#ifndef DUCKDETECTOR_COMMON_MOUNT_ID_OBSERVATION_H
#define DUCKDETECTOR_COMMON_MOUNT_ID_OBSERVATION_H

#include <cstdint>
#include <string>
#include <vector>

namespace duckdetector::common {

    struct MountIdObservation {
        int previousId;
        int currentId;
        std::string previousTarget;
        std::string currentTarget;

        [[nodiscard]] std::string detail() const {
            return "Adjacent mountinfo records: " + previousTarget + " (ID " +
                   std::to_string(previousId) + ") -> " + currentTarget + " (ID " +
                   std::to_string(currentId) +
                   "). Mount IDs need not be consecutive; this does not establish hidden mounts.";
        }
    };

    // ACK fs/namespace.c uses a global, reusable ID allocator and iterates a namespace's
    // mount list, not an ID sequence. Source (android14-6.1):
    // https://android.googlesource.com/kernel/common/+/48e3cd973485465613da6d71fa17139773546573/fs/namespace.c
    // Both startup and runtime retain the same local observations without counting
    // supposedly missing mounts or making a security inference from their magnitude.
    template<typename Entry>
    std::vector<MountIdObservation> observe_mount_id_discontinuities(
            const std::vector<Entry> &entries
    ) {
        std::vector<MountIdObservation> observations;
        for (std::size_t index = 1; index < entries.size(); ++index) {
            const auto &previous = entries[index - 1];
            const auto &current = entries[index];
            if (previous.target != "/apex/com.android.art" && current.target != "/data_mirror") {
                continue;
            }
            if (previous.id <= 0 || current.id <= 0 ||
                static_cast<std::int64_t>(current.id) - previous.id == 1) {
                continue;
            }
            observations.push_back({previous.id, current.id, previous.target, current.target});
        }
        return observations;
    }

}  // namespace duckdetector::common

#endif  // DUCKDETECTOR_COMMON_MOUNT_ID_OBSERVATION_H
