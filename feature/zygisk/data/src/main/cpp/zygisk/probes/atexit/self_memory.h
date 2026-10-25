// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>

namespace duckdetector::zygisk::atexit {
    // Kernel copy_from_user reports bad source pages without faulting the app. Unlike proc/self/mem,
    // a private pipe remains usable when the ordinary app is non-dumpable. No process flags change.
    class SelfMemory {
    public:
        SelfMemory();
        ~SelfMemory();
        SelfMemory(const SelfMemory &) = delete;
        SelfMemory &operator=(const SelfMemory &) = delete;
        bool available() const { return read_fd_ >= 0 && write_fd_ >= 0; }
        int error() const { return error_; }
        bool read(uintptr_t address, void *out, size_t bytes);

    private:
        bool fail(int error);
        int read_fd_ = -1;
        int write_fd_ = -1;
        int error_ = 0;
    };
}
