#include "ksu_wrapper_leak_probe.h"

#include <cerrno>
#include <cctype>
#include <cstdlib>
#include <limits>

namespace duckdetector::nativeroot {
bool parse_file_nr(const char *text, int64_t &allocated) {
    uint64_t values[3]{};
    for (auto &value : values) {
        while (std::isspace(static_cast<unsigned char>(*text))) ++text;
        if (*text < '0' || *text > '9') return false;
        errno = 0;
        char *end = nullptr;
        value = std::strtoull(text, &end, 10);
        if (errno || value > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) return false;
        text = end;
        if (*text && !std::isspace(static_cast<unsigned char>(*text))) return false;
    }
    while (std::isspace(static_cast<unsigned char>(*text))) ++text;
    // ACK reports zero unused objects. Other accounting models are not evaluated.
    if (*text || values[1] != 0 || values[0] == 0 || values[0] > values[2]) return false;
    allocated = static_cast<int64_t>(values[0]);
    return true;
}

WrapperLeakSample sample_wrapper_leak(WrapperLeakIo &io) {
    WrapperLeakSample result;
    auto point = [&](bool stable) {
        FileNrPoint value;
        if (!io.counter(value)) return false;
        const int previous = result.count - 1;
        result.points[result.count++] = value;
        if (value.spread > 64 || (stable && previous >= 0 &&
            (value.median - result.points[previous].median < -64 ||
             value.median - result.points[previous].median > 64))) {
            result.stage = WrapperStage::kNoisyControls;
            return false;
        }
        return true;
    };
    bool ok = point(false);
    for (int round = 0; round < kWrapperRounds && ok; ++round) {
        ok = io.settle(40) && point(true);
        for (bool wrapped : {false, true, false}) {
            if (!ok) break;
            int completed = 0;
            ok = io.cycles(wrapped, kWrapperCycles, completed);
            if (wrapped) result.reopens += completed;
            ok = ok && io.settle(40) && point(!wrapped);
        }
        if (ok) ++result.completed;
    }
    if (ok) ok = io.settle(200) && point(true);
    if (ok) result.stage = WrapperStage::kCollected;
    else if (result.stage != WrapperStage::kNoisyControls) result.stage = io.failure();
    result.error = io.error();
    if (!io.cleanup()) {
        result.stage = WrapperStage::kCleanupFailed;
        result.error = io.error();
    }
    return result;
}
}
