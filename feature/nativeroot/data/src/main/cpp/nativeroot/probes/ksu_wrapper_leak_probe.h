#pragma once

#include <array>
#include <cstdint>

namespace duckdetector::nativeroot {
constexpr int kWrapperRounds = 3;
constexpr int kWrapperCycles = 256;
// Wire codes are also validated by KernelSuWrapperLeakNativeBridge.
enum class WrapperStage {
    kCollected = 0, kNoCandidate = 1, kUnavailable = 2, kPermissionLimited = 3,
    kMalformedCounter = 4, kIoFailed = 5, kTimedOut = 6, kCleanupFailed = 7, kNoisyControls = 8
};
struct FileNrPoint { int64_t median = 0; int64_t spread = 0; };
struct WrapperLeakSample {
    WrapperStage stage = WrapperStage::kUnavailable;
    int error = 0;
    int completed = 0;
    int reopens = 0;
    // baseline, then idle/direct/reopen/direct for each round, then persistence.
    std::array<FileNrPoint, 14> points{};
    int count = 0;
};
// The sampler owns both supplied descriptors. Reopens never read or write terminal data.
struct WrapperLeakIo {
    virtual ~WrapperLeakIo() = default;
    virtual bool counter(FileNrPoint &point) = 0;
    virtual bool cycles(bool wrapped, int count, int &completed) = 0;
    virtual bool settle(int milliseconds) = 0;
    virtual bool cleanup() = 0;
    virtual WrapperStage failure() const = 0;
    virtual int error() const = 0;
};
WrapperLeakSample sample_wrapper_leak(WrapperLeakIo &io);
WrapperLeakSample collect_wrapper_leak();
bool parse_file_nr(const char *text, int64_t &allocated);
}
