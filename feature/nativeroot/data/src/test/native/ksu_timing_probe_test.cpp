/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sched.h>
#include <sys/resource.h>
#include <unistd.h>
#include <vector>

#if defined(__APPLE__)
// Host-only stand-in for Linux's fixed-size affinity mask. All scheduler
// operations below are fakes; these tests never change host thread affinity.
struct cpu_set_t { uint64_t words[16]; };
constexpr int CPU_SETSIZE = 1024;
#define CPU_ZERO(value) std::memset(value, 0, sizeof(cpu_set_t))
#define CPU_SET(cpu, value) ((value)->words[(cpu) / 64] |= (uint64_t{1} << ((cpu) % 64)))
#define CPU_ISSET(cpu, value) (((value)->words[(cpu) / 64] >> ((cpu) % 64)) & 1)
#define CPU_EQUAL(first, second) (std::memcmp(first, second, sizeof(cpu_set_t)) == 0)
#endif

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
    if ((scenario == 7 && calls == 1) || scenario == 10) return -EINTR;
    if (scenario == 11 && option == 0xDEADBEEF) return -EPERM;
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
    window.requested_cpu = 2;
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
    assert(measured.allowed == std::vector<jlong>({2, 3}));
    for (const auto &outcome : measured.outcomes) {
        assert(outcome.used == 1 && outcome.codes[0] == -EINVAL && outcome.counts[0] == 10000);
        assert(outcome.total_retries == 0 && outcome.other == 0);
    }
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
    assert(retried.outcomes[3].retried == 1 && retried.outcomes[3].total_retries == 1);
    assert(retried.outcomes[3].max_retries == 1 && retried.outcomes[3].retry_limit == 0);
    const auto exhausted = collect_case(10, true);
    assert(exhausted.status == 0 && calls == 40000);
    assert(exhausted.outcomes[0].codes[0] == -EINTR && exhausted.outcomes[0].retry_limit == 10000);
    assert(exhausted.outcomes[0].total_retries == 30000 && exhausted.outcomes[0].max_retries == 3);
    const auto intercepted = collect_case(11);
    assert(intercepted.status == 0 && intercepted.outcomes[1].codes[0] == -EPERM);
    assert(intercepted.outcomes[0].codes[0] == -EINVAL);
    Outcomes overflow;
    for (int code = 0; code < 10; ++code) overflow.record({100, code, 0});
    assert(overflow.used == 8 && overflow.other == 2);
    const auto rejected = collect_case(8);
    assert(rejected.status != 0 && calls == 0 && affinity_sets == 0);
    const auto rejected_cpu = collect_case(9, true);
    assert(rejected_cpu.status == 1 && calls == 0 && rejected_cpu.cleanup);
}
