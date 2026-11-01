// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "zygisk/common/types.h"

#include <initializer_list>

namespace duckdetector::zygisk {
    inline int count_heuristic_families(const std::initializer_list<const ProbeResult *> probes) {
        std::set<HeuristicFamily> families;
        for (const auto *probe: probes) {
            families.insert(probe->heuristic_families.begin(), probe->heuristic_families.end());
        }
        return static_cast<int>(families.size());
    }
}
