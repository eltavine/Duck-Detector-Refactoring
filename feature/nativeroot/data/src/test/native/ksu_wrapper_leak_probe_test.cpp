#include "ksu_wrapper_leak_probe.h"
#include <cassert>
#include <cerrno>
#include <string>
#include <vector>
using namespace duckdetector::nativeroot;
struct FakeIo : WrapperLeakIo {
    int calls = 0, fail_at = -1, cleanups = 0;
    bool cleanup_ok = true;
    bool noisy = false;
    bool drift = false;
    int points = 0;
    std::vector<bool> order;
    bool operation() { return ++calls != fail_at; }
    bool counter(FileNrPoint &p) override { p = {10000 + (drift ? 100 * points : 0), noisy ? 65 : 0}; ++points; return operation(); }
    bool cycles(bool w, int count, int &done) override {
        assert(count == 256); order.push_back(w);
        const bool ok = operation(); done = ok ? count : 17; return ok;
    }
    bool settle(int) override { return operation(); }
    bool cleanup() override { ++cleanups; return cleanup_ok; }
    WrapperStage failure() const override { return WrapperStage::kTimedOut; }
    int error() const override { return fail_at > 0 || !cleanup_ok ? ETIMEDOUT : 0; }
};
int main() {
    int64_t n = 0;
    assert(parse_file_nr("1000 0 99999\n", n) && n == 1000);
    for (const char *bad : {"", "1 0", "-1 0 10", "1 -0 10", "1 0 10 junk",
            "1 1 10", "0 0 10", "11 0 10", "9223372036854775808 0 99999999999999999999",
            "1.0 0 10", "1 0 10 4", "1 0 +10"}) assert(!parse_file_nr(bad, n));
    FakeIo io;
    auto good = sample_wrapper_leak(io);
    assert(good.stage == WrapperStage::kCollected && good.error == 0);
    assert(good.completed == 3 && good.count == 14 && good.reopens == 768 && io.cleanups == 1);
    assert(io.order == std::vector<bool>({false,true,false,false,true,false,false,true,false}));
    // Every possible failing operation must prevent a collected result and release ownership.
    for (int fail = 1; fail <= io.calls; ++fail) {
        FakeIo broken; broken.fail_at = fail;
        auto result = sample_wrapper_leak(broken);
        assert(result.stage == WrapperStage::kTimedOut && broken.cleanups == 1);
        assert(result.count <= 14 && result.reopens <= 768 && result.error == ETIMEDOUT);
    }
    for (bool drift : {false, true}) {
        FakeIo noisy; noisy.noisy = !drift; noisy.drift = drift;
        const auto result = sample_wrapper_leak(noisy);
        assert(result.stage == WrapperStage::kNoisyControls && result.reopens == 0 && noisy.cleanups == 1);
    }
    FakeIo cleanup; cleanup.cleanup_ok = false;
    assert(sample_wrapper_leak(cleanup).stage == WrapperStage::kCleanupFailed);
}
