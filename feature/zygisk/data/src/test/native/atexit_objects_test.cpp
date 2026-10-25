// SPDX-License-Identifier: Apache-2.0
#include "zygisk/probes/atexit/libc_objects.h"

#include <cassert>
#include <cstring>
#include <elf.h>
#include <limits>
#include <string>

using namespace duckdetector::zygisk::atexit;

#if UINTPTR_MAX == UINT64_MAX
using Header = Elf64_Ehdr;
using Section = Elf64_Shdr;
using Symbol = Elf64_Sym;
constexpr int kClass = ELFCLASS64;
#else
using Header = Elf32_Ehdr;
using Section = Elf32_Shdr;
using Symbol = Elf32_Sym;
constexpr int kClass = ELFCLASS32;
#endif
#if defined(__aarch64__)
constexpr int kMachine = EM_AARCH64;
#elif defined(__arm__)
constexpr int kMachine = EM_ARM;
#elif defined(__x86_64__)
constexpr int kMachine = EM_X86_64;
#else
constexpr int kMachine = EM_386;
#endif

template<typename T> void put(std::vector<uint8_t> &out, size_t at, const T &value) {
    assert(at + sizeof(value) <= out.size());
    std::memcpy(out.data() + at, &value, sizeof(value));
}

struct Fixture {
    std::vector<uint8_t> bytes = std::vector<uint8_t>(4096);
    Header header{};
    Section table{}, strings{}, data{};
    size_t next_symbol = 1, next_string = 1;

    Fixture() {
        std::memcpy(header.e_ident, ELFMAG, SELFMAG);
        header.e_ident[EI_CLASS] = kClass;
        header.e_ident[EI_DATA] = ELFDATA2LSB;
        header.e_ident[EI_VERSION] = EV_CURRENT;
        header.e_type = ET_DYN;
        header.e_machine = kMachine;
        header.e_version = EV_CURRENT;
        header.e_ehsize = sizeof(Header);
        header.e_shoff = 128;
        header.e_shentsize = sizeof(Section);
        header.e_shnum = 4;
        table.sh_type = SHT_SYMTAB;
        table.sh_offset = 512;
        table.sh_entsize = sizeof(Symbol);
        table.sh_link = 2;
        strings.sh_type = SHT_STRTAB;
        strings.sh_offset = 2048;
        strings.sh_size = 1024;
        data.sh_type = SHT_NOBITS;
        data.sh_addr = 0x2000;
        data.sh_size = 0x1000;
        data.sh_flags = SHF_ALLOC | SHF_WRITE;
    }

    void add(const std::string &name, uintptr_t address, size_t size) {
        Symbol symbol{};
        symbol.st_name = next_string;
        symbol.st_info = ELF32_ST_INFO(STB_LOCAL, STT_OBJECT);
        symbol.st_shndx = 3;
        symbol.st_value = address;
        symbol.st_size = size;
        put(bytes, table.sh_offset + next_symbol++ * sizeof(Symbol), symbol);
        std::memcpy(bytes.data() + strings.sh_offset + next_string, name.c_str(), name.size() + 1);
        next_string += name.size() + 1;
    }

    std::vector<uint8_t> finish() {
        table.sh_size = next_symbol * sizeof(Symbol);
        put(bytes, 0, header);
        put(bytes, header.e_shoff + sizeof(Section), table);
        put(bytes, header.e_shoff + 2 * sizeof(Section), strings);
        put(bytes, header.e_shoff + 3 * sizeof(Section), data);
        return bytes;
    }
};

int main() {
    constexpr uintptr_t base = 0x100000;
    Fixture whole;
    whole.add("_ZL7g_array", 0x2000, 4 * sizeof(uintptr_t) + 8);
    whole.add("_ZL13g_atexit_lock", 0x2080, 40);
    auto good = whole.finish();
    auto result = locate_objects(good, base);
    assert(result.state == ObjectState::kFound);
    assert(result.fields[4] == base + 0x2000 + 4 * sizeof(uintptr_t));

    Fixture split;
    for (size_t i = 0; i < 5; ++i) split.add("_ZL7g_array." + std::to_string(i), 0x2000 + i * 32,
                                             i == 4 ? 8 : sizeof(uintptr_t));
    split.add("_ZL13g_atexit_lock", 0x2200, 40);
    result = locate_objects(split.finish(), base);
    assert(result.state == ObjectState::kFound && result.fields[3] == base + 0x2060);

    Fixture aliased;
    for (size_t i = 0; i < 5; ++i) aliased.add("_ZL7g_array." + std::to_string(i), 0x2000,
                                               i == 4 ? 8 : sizeof(uintptr_t));
    aliased.add("_ZL13g_atexit_lock", 0x2200, 40);
    assert(locate_objects(aliased.finish(), base).state == ObjectState::kMalformed);

    Fixture lock_overlap;
    lock_overlap.add("_ZL7g_array", 0x2000, 4 * sizeof(uintptr_t) + 8);
    lock_overlap.add("_ZL13g_atexit_lock", 0x2000, 40);
    assert(locate_objects(lock_overlap.finish(), base).state == ObjectState::kMalformed);

    Fixture unaligned;
    unaligned.add("_ZL7g_array", 0x2001, 4 * sizeof(uintptr_t) + 8);
    unaligned.add("_ZL13g_atexit_lock", 0x2080, 40);
    assert(locate_objects(unaligned.finish(), base).state == ObjectState::kMalformed);

    split.add("_ZL7g_array.0", 0x2400, sizeof(uintptr_t));
    assert(locate_objects(split.finish(), base).state == ObjectState::kMalformed);
    assert(locate_objects(good, std::numeric_limits<uintptr_t>::max() - 1).state == ObjectState::kMalformed);
    assert(locate_objects({}, base).state == ObjectState::kMalformed);

    auto bad = good;
    bad[EI_CLASS] = kClass == ELFCLASS64 ? ELFCLASS32 : ELFCLASS64;
    assert(locate_objects(bad, base).state == ObjectState::kMalformed);
    whole.header.e_shoff = std::numeric_limits<decltype(Header::e_shoff)>::max();
    put(bad, 0, whole.header);
    assert(locate_objects(bad, base).state == ObjectState::kMalformed);

    Fixture stripped;
    stripped.table.sh_type = SHT_DYNSYM;
    assert(locate_objects(stripped.finish(), base).state == ObjectState::kMissing);
    stripped.header.e_shnum = 0;
    stripped.header.e_shentsize = 0;
    stripped.header.e_shoff = 0;
    put(stripped.bytes, 0, stripped.header);
    assert(locate_objects(stripped.bytes, base).state == ObjectState::kMissing);
    Fixture no_lock;
    no_lock.add("_ZL7g_array", 0x2000, 4 * sizeof(uintptr_t) + 8);
    assert(locate_objects(no_lock.finish(), base).state == ObjectState::kMissing);
    Fixture corrupt;
    corrupt.add("_ZL7g_array", 0x2000, 4 * sizeof(uintptr_t) + 8);
    corrupt.add("_ZL13g_atexit_lock", 0x2080, 40);
    corrupt.strings.sh_offset = corrupt.bytes.size() - 1;
    assert(locate_objects(corrupt.finish(), base).state == ObjectState::kMalformed);
}
