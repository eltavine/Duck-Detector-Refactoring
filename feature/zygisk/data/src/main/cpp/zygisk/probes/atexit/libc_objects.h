// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace duckdetector::zygisk::atexit {

    enum class ObjectState { kFound, kMissing, kMalformed };

    struct LibcObjects {
        ObjectState state = ObjectState::kMissing;
        // Pointer, size, extracted count, capacity, total appends; each address is independent.
        std::array<uintptr_t, 5> fields{};
        uintptr_t mutex = 0;
        size_t mutex_size = 0;
    };

    LibcObjects locate_objects(const std::vector<uint8_t> &image, uintptr_t load_bias);

}  // namespace duckdetector::zygisk::atexit
