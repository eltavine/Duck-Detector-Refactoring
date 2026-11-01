// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "zygisk/common/types.h"

namespace duckdetector::zygisk::atexit {

    using TableState = AtexitTableState;

    struct Entry {
        uintptr_t function = 0;
        uintptr_t argument = 0;
        uintptr_t dso = 0;

        bool empty() const { return function == 0 && argument == 0 && dso == 0; }
    };

    struct Table {
        TableState state = TableState::kNotCollected;
        std::string detail;
        std::vector<Entry> entries;
    };

    struct Evidence {
        bool bounded = false;
        bool dense_clearing = false;
        size_t null_entries = 0;
        size_t anchored_gaps = 0;
        size_t anonymous_callbacks = 0;
        size_t unresolved_callbacks = 0;
        std::vector<Trace> traces;
    };

    const char *state_name(TableState state);
    Table read_table(const std::vector<MapEntry> &maps);
    Evidence interpret_table(const std::vector<Entry> &entries, const std::vector<MapEntry> &maps);

}  // namespace duckdetector::zygisk::atexit
