// SPDX-License-Identifier: Apache-2.0
#include "selinuxpolicy/avc_lookup_probe.h"
#include <cerrno>
#include <cstring>

namespace duckdetector::selinux::avc_lookup {
    namespace {
        constexpr char kStatsHeader[] = "lookups hits misses allocations reclaims frees\n";
        bool number(const char *&cursor, const char *end, uint32_t &value) {
            if (cursor == end || *cursor < '0' || *cursor > '9') return false;
            uint64_t parsed = 0;
            for (; cursor < end && *cursor >= '0' && *cursor <= '9'; ++cursor) {
                parsed = parsed * 10 + static_cast<unsigned>(*cursor - '0');
                if (parsed > UINT32_MAX) return false;
            }
            value = static_cast<uint32_t>(parsed);
            return true;
        }

    }

    // ACK selinuxfs (sel_avc_stats_seq_show) prints this header and then, for each possible CPU in
    // ascending order, "%u %u %u %u %u %u\n" with hits computed as lookups - misses.
    int parse_cache_stats(const char *text, const size_t length, CacheStats &stats) {
        stats = CacheStats{};
        constexpr size_t header = sizeof(kStatsHeader) - 1;
        if (length < header || std::memcmp(text, kStatsHeader, header) != 0) return EPROTO;
        const char *cursor = text + header;
        const char *const end = text + length;
        while (cursor < end) {
            if (stats.rows == kCpuLimit) return E2BIG;
            uint32_t columns[6];
            for (unsigned column = 0; column < 6; ++column) {
                if (!number(cursor, end, columns[column])) return EPROTO;
                if (cursor == end || *cursor != (column == 5 ? '\n' : ' ')) return EPROTO;
                ++cursor;
            }
            // A row whose hits and misses do not add up to its first column is not this format.
            if (static_cast<uint32_t>(columns[1] + columns[2]) != columns[0]) return EPROTO;
            stats.lookups[stats.rows++] = columns[0];
        }
        return stats.rows > 0 ? 0 : ENODATA;
    }

    // drivers/base/cpu.c prints cpu_possible_mask as a cpulist: ascending "n" or "n-m" items joined
    // by commas and ended by a newline.
    int parse_cpu_list(const char *text, const size_t length, CpuMask &mask) {
        mask = CpuMask{};
        const char *cursor = text;
        const char *const end = text + length;
        int64_t previous = -1;
        while (true) {
            uint32_t first = 0;
            if (!number(cursor, end, first)) return EPROTO;
            uint32_t last = first;
            if (cursor < end && *cursor == '-') {
                ++cursor;
                if (!number(cursor, end, last)) return EPROTO;
            }
            if (static_cast<int64_t>(first) <= previous || last < first) return EPROTO;
            if (last >= kCpuLimit) return E2BIG;
            for (uint32_t cpu = first; cpu <= last; ++cpu) mask.possible[cpu] = true;
            mask.count += last - first + 1;
            previous = last;
            if (cursor == end || *cursor != ',') break;
            ++cursor;
        }
        if (cursor < end && *cursor == '\n') ++cursor;
        return cursor == end ? 0 : EPROTO;
    }

    int stats_row(const CpuMask &mask, const int cpu) {
        if (cpu < 0 || cpu >= static_cast<int>(kCpuLimit) || !mask.possible[cpu]) return -1;
        int row = 0;
        for (int index = 0; index < cpu; ++index) row += mask.possible[index] ? 1 : 0;
        return row;
    }

}
