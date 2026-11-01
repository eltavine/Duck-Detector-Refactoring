// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstddef>
#include <cstdint>

// A deterministic empty loader inventory for host-only maps/loader comparisons.
using Elf64_Half = uint16_t;
struct Elf64_Phdr {
    uint32_t p_type;
    uintptr_t p_vaddr;
    uintptr_t p_memsz;
};
#define ElfW(type) Elf64_##type
constexpr uint32_t PT_LOAD = 1;
struct dl_phdr_info {
    uintptr_t dlpi_addr;
    const char *dlpi_name;
    const Elf64_Phdr *dlpi_phdr;
    Elf64_Half dlpi_phnum;
};
extern "C" int dl_iterate_phdr(int (*callback)(dl_phdr_info *, size_t, void *), void *data);
