// SPDX-License-Identifier: Apache-2.0
#include "zygisk/probes/atexit/libc_objects.h"

#include <algorithm>
#include <cstring>
#include <elf.h>
#include <limits>
#include <string_view>

namespace duckdetector::zygisk::atexit {
    namespace {
#if UINTPTR_MAX == UINT64_MAX
        using Header = Elf64_Ehdr;
        using Section = Elf64_Shdr;
        using Symbol = Elf64_Sym;
        constexpr uint8_t kClass = ELFCLASS64;
#else
        using Header = Elf32_Ehdr;
        using Section = Elf32_Shdr;
        using Symbol = Elf32_Sym;
        constexpr uint8_t kClass = ELFCLASS32;
#endif
#if defined(__aarch64__)
        constexpr uint16_t kMachine = EM_AARCH64;
#elif defined(__arm__)
        constexpr uint16_t kMachine = EM_ARM;
#elif defined(__x86_64__)
        constexpr uint16_t kMachine = EM_X86_64;
#elif defined(__i386__)
        constexpr uint16_t kMachine = EM_386;
#else
        constexpr uint16_t kMachine = EM_NONE;
#endif

        bool range(const uint64_t offset, const uint64_t count, const size_t size) {
            return offset <= size && count <= size - offset;
        }

        template<typename T>
        bool take(const std::vector<uint8_t> &image, uint64_t offset, T &value) {
            if (!range(offset, sizeof(T), image.size())) return false;
            std::memcpy(&value, image.data() + offset, sizeof(T));
            return true;
        }

        bool address(const Symbol &symbol, const Section &section, uintptr_t bias, uintptr_t &out) {
            if ((section.sh_flags & (SHF_ALLOC | SHF_WRITE)) != (SHF_ALLOC | SHF_WRITE) ||
                symbol.st_value < section.sh_addr || symbol.st_size == 0 ||
                !range(symbol.st_value - section.sh_addr, symbol.st_size, section.sh_size) ||
                symbol.st_value > std::numeric_limits<uintptr_t>::max() - bias ||
                symbol.st_size > std::numeric_limits<uintptr_t>::max() - bias - symbol.st_value) return false;
            out = bias + symbol.st_value;
            return true;
        }
    }

    LibcObjects locate_objects(const std::vector<uint8_t> &image, const uintptr_t bias) {
        LibcObjects out;
        Header header{};
        if (!take(image, 0, header) || std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
            header.e_ident[EI_CLASS] != kClass || header.e_ident[EI_DATA] != ELFDATA2LSB ||
            header.e_ident[EI_VERSION] != EV_CURRENT || header.e_type != ET_DYN ||
            header.e_machine != kMachine || header.e_version != EV_CURRENT ||
            header.e_ehsize != sizeof(Header)) {
            out.state = ObjectState::kMalformed;
            return out;
        }
        // No compressed debug data or guessed offsets: stripped/private layouts stay unsupported.
        if (header.e_shnum == 0) return out;
        if (header.e_shentsize != sizeof(Section) ||
            !range(header.e_shoff, uint64_t(header.e_shnum) * sizeof(Section), image.size())) {
            out.state = ObjectState::kMalformed;
            return out;
        }
        std::array<uintptr_t, 5> split{};
        uintptr_t whole = 0;
        bool conflict = false;
        auto assign = [&](uintptr_t &slot, uintptr_t value) {
            if (slot != 0 && slot != value) conflict = true;
            slot = value;
        };
        for (size_t si = 0; si < header.e_shnum; ++si) {
            Section table{};
            take(image, header.e_shoff + si * sizeof(Section), table);
            if (table.sh_type != SHT_SYMTAB) continue;
            Section strings{};
            if (table.sh_link >= header.e_shnum || table.sh_entsize != sizeof(Symbol) ||
                table.sh_size % sizeof(Symbol) != 0 ||
                !range(table.sh_offset, table.sh_size, image.size()) ||
                !take(image, header.e_shoff + table.sh_link * sizeof(Section), strings) ||
                strings.sh_type != SHT_STRTAB ||
                !range(strings.sh_offset, strings.sh_size, image.size())) {
                out.state = ObjectState::kMalformed;
                return out;
            }
            for (size_t pos = 0; pos < table.sh_size; pos += sizeof(Symbol)) {
                Symbol symbol{};
                take(image, table.sh_offset + pos, symbol);
                if (ELF32_ST_TYPE(symbol.st_info) != STT_OBJECT ||
                    symbol.st_shndx == SHN_UNDEF || symbol.st_shndx >= header.e_shnum) continue;
                if (symbol.st_name >= strings.sh_size) {
                    out.state = ObjectState::kMalformed;
                    return out;
                }
                const char *start = reinterpret_cast<const char *>(image.data() + strings.sh_offset + symbol.st_name);
                const auto *end = static_cast<const char *>(std::memchr(start, 0, strings.sh_size - symbol.st_name));
                if (end == nullptr) {
                    out.state = ObjectState::kMalformed;
                    return out;
                }
                const std::string_view name(start, end - start);
                const bool is_whole = name == "_ZL7g_array";
                const bool is_lock = name == "_ZL13g_atexit_lock";
                constexpr std::string_view prefix = "_ZL7g_array.";
                const bool is_split = name.size() == prefix.size() + 1 &&
                    name.substr(0, prefix.size()) == prefix && name.back() >= '0' && name.back() <= '4';
                if (!is_whole && !is_lock && !is_split) continue;
                Section section{};
                uintptr_t value = 0;
                take(image, header.e_shoff + symbol.st_shndx * sizeof(Section), section);
                if (!address(symbol, section, bias, value)) {
                    out.state = ObjectState::kMalformed;
                    return out;
                }
                if (is_whole && symbol.st_size == 4 * sizeof(uintptr_t) + sizeof(uint64_t)) assign(whole, value);
                if (is_lock) {
                    assign(out.mutex, value);
                    out.mutex_size = symbol.st_size;
                }
                if (is_split) {
                    const size_t field = name.back() - '0';
                    if (symbol.st_size == (field == 4 ? sizeof(uint64_t) : sizeof(uintptr_t))) assign(split[field], value);
                }
            }
        }
        for (size_t i = 0; i < split.size(); ++i) {
            const uintptr_t expected = whole == 0 ? 0 : whole + i * sizeof(uintptr_t);
            if (split[i] != 0 && expected != 0 && split[i] != expected) conflict = true;
            out.fields[i] = split[i] != 0 ? split[i] : expected;
        }
        if (conflict) out.state = ObjectState::kMalformed;
        else if (out.mutex != 0 && std::all_of(out.fields.begin(), out.fields.end(), [](auto p) { return p != 0; })) {
            bool distinct = true;
            for (size_t i = 0; i < out.fields.size(); ++i) {
                const size_t bytes = i == 4 ? sizeof(uint64_t) : sizeof(uintptr_t);
                const size_t alignment = i == 4 ? alignof(uint64_t) : alignof(uintptr_t);
                const uintptr_t start = out.fields[i], end = start + bytes;
                distinct = distinct && start % alignment == 0 &&
                    !(start < out.mutex + out.mutex_size && out.mutex < end);
                for (size_t j = 0; j < i; ++j) {
                    const size_t other_bytes = j == 4 ? sizeof(uint64_t) : sizeof(uintptr_t);
                    distinct = distinct && !(start < out.fields[j] + other_bytes && out.fields[j] < end);
                }
            }
            out.state = distinct ? ObjectState::kFound : ObjectState::kMalformed;
        }
        return out;
    }
}  // namespace duckdetector::zygisk::atexit
