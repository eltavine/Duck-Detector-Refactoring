#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sched.h>
#include <sys/resource.h>
#include <unistd.h>
#include <vector>

static cpu_set_t mask;
static uint64_t test_frequency;
static uint64_t clock_ticks;
static int calls;
static int affinity_sets;
static int scenario;
static int reported_cpu;
static bool preflight_run;
static int uid_value;

static uint64_t test_counter() { return clock_ticks += 100; }
static long test_prctl(uint64_t option, int command, const char *path) {
    if (preflight_run) {
        assert(option == 0xDEADBEEF && command == 1);
        assert(path && std::strcmp(path, "/data/data/com.android.keychain") == 0);
    } else {
        static const uint64_t order[] = {0xDEADBEED, 0xDEADBEEE, 0xDEADBEED, 0xDEADBEEF, 0xDEADBEED, 0xDEADBEEE};
        assert(option == order[(calls - (scenario == 7 && calls > 0 ? 1 : 0)) % 6]);
        assert(command == 7 && !path);
    }
    ++calls;
    if (scenario == 7 && calls == 1) return -EINTR;
    return -EINVAL;
}
static uid_t test_getuid() { return uid_value; }
static uid_t test_geteuid() { return uid_value; }
static int test_sched_getaffinity(pid_t, size_t, cpu_set_t *result) {
    if (scenario == 1) return -1;
    *result = mask;
    return 0;
}
static int test_sched_setaffinity(pid_t, size_t, const cpu_set_t *value) {
    ++affinity_sets;
    if (((scenario == 2 || scenario == 9) && affinity_sets == 1) || (scenario == 6 && affinity_sets == 2)) {
        errno = EINVAL;
        return -1;
    }
    mask = *value;
    return 0;
}
static int test_sched_getcpu() { return scenario == 3 ? 4 : reported_cpu; }
static int test_setpriority(int, id_t, int priority) { assert(priority == 20); return scenario == 4 ? -1 : 0; }
static int test_getpriority(int, id_t) { return 19; }

#define DUCKDETECTOR_KSU_TIMING_TEST
#define getuid test_getuid
#define geteuid test_geteuid
#define sched_getaffinity test_sched_getaffinity
#define sched_setaffinity test_sched_setaffinity
#define sched_getcpu test_sched_getcpu
#define setpriority test_setpriority
#define getpriority test_getpriority
#include "../../main/cpp/nativeroot/ksu_timing_native_bridge.cpp"

static Window collect_case(int kind, bool preflight = false) {
    scenario = kind;
    affinity_sets = 0;
    calls = 0;
    clock_ticks = 0;
    uid_value = kind == 8 ? 0 : 10000;
    test_frequency = kind == 5 ? 0 : 19200000;
    reported_cpu = kind == 9 ? 3 : 2;
    preflight_run = preflight;
    CPU_ZERO(&mask);
    CPU_SET(2, &mask);
    CPU_SET(3, &mask);
    Window window;
    window.requested_cpu = preflight ? -1 : 2;
    window.preflight = preflight;
    window.ticks.resize(sample_count * (preflight ? 1 : 6));
    collect(window);
    return window;
}

int main() {
    auto measured = collect_case(0);
    assert(measured.status == 0 && measured.cleanup && calls == 60000 && measured.actual_cpu == 2);
    assert(measured.ticks.size() == 60000);
    for (auto ticks : measured.ticks) assert(ticks == 100);
    assert(CPU_ISSET(2, &mask) && CPU_ISSET(3, &mask));
    auto preflight = collect_case(0, true);
    assert(preflight.status == 0 && preflight.cleanup && calls == 10000);
    for (int kind = 1; kind <= 6; ++kind) {
        const auto failed = collect_case(kind);
        assert(failed.status != 0);
        assert(failed.cleanup == (kind != 6));
        if (kind != 6) assert(calls == 0);
    }
    const auto retried = collect_case(7);
    assert(retried.status == 0 && retried.cleanup && calls == 60001);
    const auto rejected = collect_case(8);
    assert(rejected.status != 0 && calls == 0 && affinity_sets == 0);
    const auto next_allowed = collect_case(9, true);
    assert(next_allowed.status == 0 && next_allowed.actual_cpu == 3 && next_allowed.cleanup);
}
