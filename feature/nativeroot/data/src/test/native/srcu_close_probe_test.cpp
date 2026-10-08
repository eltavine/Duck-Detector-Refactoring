// Exercises acquisition ordering and error handling with injected I/O, not kernel SRCU semantics.
#include "srcu_close_probe.h"
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <thread>

using namespace duckdetector::nativeroot;
namespace {
std::atomic<int> opened{0}, closed{0}, watched{0};
int failure = 0;
int init() {
    if (failure == 1) { errno = EMFILE; return -1; }
    ++opened;
    return 42;
}
int watch(int, const char *) {
    if (failure == 2) { errno = EACCES; return -1; }
    ++watched;
    return 1;
}
int close_fd(int) {
    ++closed;
    if (failure == 4) { errno = EINTR; return -1; }
    return 0;
}
std::int64_t now() {
    if (failure == 3) { errno = EINVAL; return 0; }
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
void pause() { std::this_thread::yield(); }
const CloseIo io{init, watch, close_fd, now, pause};
void reset(int value) { failure = value; opened = 0; closed = 0; watched = 0; }
void await_closes(int count) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (closed < count && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
    assert(closed >= count);
}
}
int main() {
    for (int mode : {1, 2}) {
        reset(mode);
        bool triggered = false;
        auto window = measure_close_window("private", [&] { triggered = true; }, &io);
        assert(!triggered && window.samples.size() == 1);
        assert(window.samples[0].stage == (mode == 1 ? CloseStage::INIT_FAILED : CloseStage::WATCH_FAILED));
        assert(window.samples[0].error == (mode == 1 ? EMFILE : EACCES));
        assert(opened == closed);
    }
    reset(3);
    bool triggered = false;
    auto bad_clock = measure_close_window("private", [&] { triggered = true; }, &io);
    assert(!triggered && bad_clock.samples[0].stage == CloseStage::CLOCK_FAILED);
    assert(bad_clock.samples[0].error == EINVAL && opened == closed);
    reset(4);
    auto bad_close = measure_close_window("private", [&] { await_closes(1); }, &io);
    assert(bad_close.samples.size() == 1);
    assert(bad_close.samples[0].stage == CloseStage::CLOSE_FAILED);
    assert(bad_close.samples[0].error == EINTR && opened == 1 && closed == 1);
    reset(0);
    auto normal = measure_close_window("private", [&] {
        assert(watched >= 1); // The first FD and mark exist before the stimulus starts.
        await_closes(8);
    }, &io);
    assert(normal.end >= normal.begin && opened == closed);
    assert(normal.samples.size() >= 8);
    for (const auto &sample : normal.samples) {
        assert(sample.stage == CloseStage::OK && sample.end >= sample.begin);
        assert(sample.begin >= normal.begin);
    }
    reset(0);
    auto quota = measure_close_window("private", [&] { await_closes(128); }, &io);
    assert(quota.saturated && quota.samples.size() == 128 && opened == closed);
}
