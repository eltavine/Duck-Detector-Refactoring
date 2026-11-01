// SPDX-License-Identifier: Apache-2.0
#include "zygisk/probes/atexit/self_memory.h"

#include <array>
#include <cassert>
#include <cerrno>
#include <limits>
#include <sys/mman.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif

using duckdetector::zygisk::atexit::SelfMemory;

int main() {
#if defined(__linux__)
    const int previous_dumpable = prctl(PR_GET_DUMPABLE);
    assert(previous_dumpable >= 0);
    assert(prctl(PR_SET_DUMPABLE, 0) == 0);
#endif
    std::array<unsigned char, 12345> source{}, destination{};
    for (size_t i = 0; i < source.size(); ++i) source[i] = static_cast<unsigned char>(i * 19);
    SelfMemory memory;
    assert(memory.available());
    assert(memory.read(reinterpret_cast<uintptr_t>(source.data()), destination.data(), source.size()));
    assert(source == destination);
    assert(memory.read(0, destination.data(), 0));
    assert(memory.read(reinterpret_cast<uintptr_t>(source.data()), destination.data(), 1));

    const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    void *inaccessible = mmap(nullptr, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(inaccessible != MAP_FAILED);
    SelfMemory bad_page;
    assert(!bad_page.read(reinterpret_cast<uintptr_t>(inaccessible), destination.data(), 1));
    assert(bad_page.error() == EFAULT);
    assert(!bad_page.available());
    assert(!bad_page.read(reinterpret_cast<uintptr_t>(source.data()), destination.data(), 1));
    assert(munmap(inaccessible, page_size) == 0);

    SelfMemory overflow;
    assert(!overflow.read(std::numeric_limits<uintptr_t>::max(), destination.data(), 2));
    assert(overflow.error() == EFAULT);
#if defined(__linux__)
    assert(prctl(PR_GET_DUMPABLE) == 0);
    assert(prctl(PR_SET_DUMPABLE, previous_dumpable) == 0);
#endif
}
