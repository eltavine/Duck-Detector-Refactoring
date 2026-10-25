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

#include <jni.h>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr size_t sample_count = 10000;
constexpr int maximum_retries = 3;
struct Measurement {
    uint64_t ticks;
    long result;
    int retries;
};
struct Outcomes {
    std::array<long, 8> codes{};
    std::array<int, 8> counts{};
    int used = 0;
    int other = 0;
    int retried = 0;
    int total_retries = 0;
    int max_retries = 0;
    int retry_limit = 0;
    void record(const Measurement &value) {
        int bin = 0;
        while (bin < used && codes[bin] != value.result) ++bin;
        if (bin < used) ++counts[bin];
        else if (used < 8) { codes[used] = value.result; counts[used++] = 1; }
        else ++other;
        if (value.retries > 0) ++retried;
        total_retries += value.retries;
        if (value.retries > max_retries) max_retries = value.retries;
        if (value.result == -EINTR && value.retries == maximum_retries) ++retry_limit;
    }
    void append(std::vector<jlong> &header) const {
        header.push_back(used);
        for (int i = 0; i < used; ++i) { header.push_back(codes[i]); header.push_back(counts[i]); }
        header.insert(header.end(), {other, retried, total_retries, max_retries, retry_limit});
    }
};
struct Window {
    int requested_cpu = -1;
    bool preflight = false;
    int status = 4;
    int actual_cpu = -1;
    uint64_t frequency = 0;
    bool cleanup = true;
    std::vector<jlong> ticks;
    std::vector<jlong> allowed;
    std::vector<Outcomes> outcomes;
};

#if defined(__aarch64__) || defined(DUCKDETECTOR_KSU_TIMING_TEST)
static_assert(sizeof(cpu_set_t) == 128);

// Prevent inlining into sampling call sites, keeping the measurement in a
// separate function body; this does not disable other compiler optimizations.
// DUCKDETECTOR_KSU_TIMING_TEST replaces counter reads and prctl with
// deterministic host-test helpers, exercising the same control flow without
// ARM64 instructions.
__attribute__((noinline)) Measurement measure(uint64_t option, bool preflight) {
    uint64_t begin;
    uint64_t end;
    const char path[] = "/data/data/com.android.keychain";
#if defined(DUCKDETECTOR_KSU_TIMING_TEST)
    begin = test_counter();
#else
    // Read fixed-frequency virtual timer ticks, not CPU cycles. ISB brackets
    // the read to order instruction execution at the timing boundary. volatile
    // keeps the asm observable; "memory" constrains compiler memory reordering,
    // but is not itself a hardware memory barrier.
    asm volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(begin) :: "memory");
#endif
    long result;
    int retries = 0;
    do {
#if defined(DUCKDETECTOR_KSU_TIMING_TEST)
        result = test_prctl(option, preflight ? 1 : 7, preflight ? path : nullptr);
#else
    // Linux ARM64 syscall ABI: x8 selects prctl (167), x0-x4 carry its five
    // arguments, and x0 receives the raw result. x5 is an unused sixth slot.
    // Direct SVC avoids libc wrapper/errno overhead in this short measurement;
    // ordinary prctl() is functional too, but adds a different userspace path.
        register uint64_t arg0 asm("x0") = option;
        register uint64_t arg1 asm("x1") = preflight ? 1 : 7;
        register uint64_t arg2 asm("x2") = preflight ? reinterpret_cast<uint64_t>(path) : 0;
        register uint64_t arg3 asm("x3") = 0;
        register uint64_t arg4 asm("x4") = 0;
        register uint64_t arg5 asm("x5") = 0;
        register uint64_t number asm("x8") = 167;
        // SVC #0 enters the kernel; the syscall number is in x8, not the
        // immediate. "+r" makes x0 both input and output; the other operands
        // supply fixed register inputs. "memory" covers pointed-to data; "cc"
        // clobbers flags.
        asm volatile("svc #0" : "+r"(arg0) : "r"(arg1), "r"(arg2), "r"(arg3),
                "r"(arg4), "r"(arg5), "r"(number) : "memory", "cc");
        // Raw syscalls return negative errno values instead of setting libc
        // errno.
        result = static_cast<long>(arg0);
#endif
    // -EINTR can result when a signal interrupts an interruptible kernel wait
    // and the syscall is not automatically restarted. Signal delivery alone
    // does not imply -EINTR; an unsupported prctl option normally returns
    // -EINVAL instead. Bound retries; any retried sample is inconclusive.
    } while (result == -EINTR && retries++ < maximum_retries);
    if (retries > maximum_retries) retries = maximum_retries;
#if defined(DUCKDETECTOR_KSU_TIMING_TEST)
    end = test_counter();
#else
    // Match the start boundary; the interval also includes setup and EINTR
    // retries.
    asm volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(end) :: "memory");
#endif
    return {end - begin, result, retries};
}

bool restore(const cpu_set_t &saved) {
    int result;
    do { result = sched_setaffinity(0, sizeof(saved), &saved); } while (result < 0 && errno == EINTR);
    cpu_set_t current;
    return result == 0 && sched_getaffinity(0, sizeof(current), &current) == 0 && CPU_EQUAL(&saved, &current);
}

void collect(Window &window) {
    const auto app_id = getuid() % 100000;
    if (app_id < 10000 || app_id > 19999 || geteuid() != getuid()) return;
    cpu_set_t saved;
    if (sched_getaffinity(0, sizeof(saved), &saved) != 0) { window.status = 1; return; }
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &saved)) window.allowed.push_back(cpu);
    }
    int selected = window.requested_cpu;
    cpu_set_t requested;
    auto bind = [&](int cpu) {
        CPU_ZERO(&requested);
        CPU_SET(cpu, &requested);
        int result;
        do { result = sched_setaffinity(0, sizeof(requested), &requested); } while (result != 0 && errno == EINTR);
        return result == 0;
    };
    if (selected < 0 || selected >= CPU_SETSIZE || !CPU_ISSET(selected, &saved)) {
        window.status = 1;
        return;
    }
    if (!bind(selected)) {
        window.status = 1;
        window.cleanup = restore(saved);
        return;
    }
    window.cleanup = false;
    cpu_set_t current;
    window.actual_cpu = sched_getcpu();
    if (sched_getaffinity(0, sizeof(current), &current) != 0 || !CPU_EQUAL(&requested, &current) ||
            window.actual_cpu != selected) {
        window.status = 2;
    } else if (setpriority(PRIO_PROCESS, 0, 20) != 0 || getpriority(PRIO_PROCESS, 0) != 19) {
        window.status = 4;
    } else {
    #if defined(DUCKDETECTOR_KSU_TIMING_TEST)
        window.frequency = test_frequency;
    #else
        asm volatile("mrs %0, cntfrq_el0" : "=r"(window.frequency));
    #endif
        if (window.frequency == 0) {
            window.status = 3;
        } else {
            window.outcomes.resize(window.preflight ? 1 : 6);
            auto sample = [&](size_t vector, size_t index, uint64_t option) {
                const auto value = measure(option, window.preflight);
                window.ticks[vector * sample_count + index] = static_cast<jlong>(value.ticks);
                // Summarize outside the timed interval, without per-sample allocation.
                window.outcomes[vector].record(value);
            };
            for (size_t index = 0; index < sample_count; ++index) {
                if (window.preflight) {
                    sample(0, index, 0xDEADBEEF);
                } else {
                    sample(3, index, 0xDEADBEED);
                    sample(0, index, 0xDEADBEEE);
                    sample(4, index, 0xDEADBEED);
                    sample(1, index, 0xDEADBEEF);
                    sample(5, index, 0xDEADBEED);
                    sample(2, index, 0xDEADBEEE);
                }
            }
            window.status = sched_getcpu() == selected ? 0 : 2;
        }
    }
    window.cleanup = restore(saved);
    if (!window.cleanup) window.status = 5;
    if (window.status != 0) window.ticks.clear();
}
#endif

void *run(void *argument) {
    auto &window = *static_cast<Window *>(argument);
#if defined(__aarch64__) || defined(DUCKDETECTOR_KSU_TIMING_TEST)
    collect(window);
#else
    window.status = 6;
#endif
    return nullptr;
}
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_KernelSuTimingNativeBridge_nativeSample(
        JNIEnv *env, jobject, jint cpu, jboolean preflight) {
    Window window;
    window.requested_cpu = cpu;
    window.preflight = preflight == JNI_TRUE;
    if (cpu < 0 || cpu >= CPU_SETSIZE) return nullptr;
    try {
        window.ticks.resize(sample_count * (window.preflight ? 1 : 6));
    } catch (...) { return nullptr; }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, run, &window) == 0) {
        if (pthread_join(thread, nullptr) != 0) std::abort();
    }
    if (window.status != 0) window.ticks.clear();
    // Private JNI protocol v2: worker affinity and bounded outcome summaries
    // precede raw vectors. Binder receives only the later Kotlin summaries.
    std::vector<jlong> header{2, window.status, window.actual_cpu,
        static_cast<jlong>(window.frequency), window.cleanup ? 1 : 0,
        static_cast<jlong>(window.allowed.size())};
    header.insert(header.end(), window.allowed.begin(), window.allowed.end());
    header.push_back(static_cast<jlong>(window.outcomes.size()));
    for (const auto &summary : window.outcomes) summary.append(header);
    header.push_back(static_cast<jlong>(window.ticks.size()));
    const auto result = env->NewLongArray(static_cast<jsize>(window.ticks.size() + header.size()));
    if (!result) return nullptr;
    env->SetLongArrayRegion(result, 0, static_cast<jsize>(header.size()), header.data());
    if (!env->ExceptionCheck() && !window.ticks.empty()) {
        env->SetLongArrayRegion(result, static_cast<jsize>(header.size()),
            static_cast<jsize>(window.ticks.size()), window.ticks.data());
    }
    return env->ExceptionCheck() ? nullptr : result;
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_eltavine_duckdetector_features_nativeroot_data_native_KernelSuTimingNativeBridge_nativeAffinity(
        JNIEnv *env, jobject) {
    cpu_set_t mask;
    std::vector<jlong> values;
    if (sched_getaffinity(0, sizeof(mask), &mask) != 0) {
        values.push_back(errno);
    } else {
        values.push_back(0);
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) if (CPU_ISSET(cpu, &mask)) values.push_back(cpu);
    }
    const auto result = env->NewLongArray(static_cast<jsize>(values.size()));
    if (!result) return nullptr;
    env->SetLongArrayRegion(result, 0, static_cast<jsize>(values.size()), values.data());
    return env->ExceptionCheck() ? nullptr : result;
}
