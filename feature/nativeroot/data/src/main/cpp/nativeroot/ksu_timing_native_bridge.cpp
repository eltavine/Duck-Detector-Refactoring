#include <jni.h>
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
struct Window {
    int requested_cpu = -1;
    bool preflight = false;
    int status = 4;
    int actual_cpu = -1;
    uint64_t frequency = 0;
    bool cleanup = true;
    std::vector<jlong> ticks;
};

#if defined(__aarch64__) || defined(DUCKDETECTOR_KSU_TIMING_TEST)
static_assert(sizeof(cpu_set_t) == 128);

// Prevent inlining into sampling call sites, keeping the measurement in a
// separate function body; this does not disable other compiler optimizations.
// DUCKDETECTOR_KSU_TIMING_TEST replaces counter reads and prctl with
// deterministic host-test helpers, exercising the same control flow without
// ARM64 instructions.
__attribute__((noinline)) uint64_t measure(uint64_t option, bool preflight) {
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
    // -EINVAL instead. Retry only -EINTR; all other results exit.
    } while (result == -EINTR);
#if defined(DUCKDETECTOR_KSU_TIMING_TEST)
    end = test_counter();
#else
    // Match the start boundary; the interval also includes setup and EINTR
    // retries.
    asm volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(end) :: "memory");
#endif
    return end - begin;
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
    int selected = window.requested_cpu;
    cpu_set_t requested;
    auto bind = [&](int cpu) {
        CPU_ZERO(&requested);
        CPU_SET(cpu, &requested);
        int result;
        do { result = sched_setaffinity(0, sizeof(requested), &requested); } while (result != 0 && errno == EINTR);
        return result == 0;
    };
    if (selected == -1) {
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            if (!CPU_ISSET(cpu, &saved)) continue;
            if (bind(cpu)) { selected = cpu; break; }
            if (!restore(saved)) { window.status = 5; window.cleanup = false; return; }
        }
    }
    if (selected < 0 || selected >= CPU_SETSIZE || !CPU_ISSET(selected, &saved)) {
        window.status = 1;
        return;
    }
    if (window.requested_cpu != -1 && !bind(selected)) {
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
            for (size_t index = 0; index < sample_count; ++index) {
                if (window.preflight) {
                    window.ticks[index] = static_cast<jlong>(measure(0xDEADBEEF, true));
                } else {
                    window.ticks[3 * sample_count + index] = static_cast<jlong>(measure(0xDEADBEED, false));
                    window.ticks[index] = static_cast<jlong>(measure(0xDEADBEEE, false));
                    window.ticks[4 * sample_count + index] = static_cast<jlong>(measure(0xDEADBEED, false));
                    window.ticks[sample_count + index] = static_cast<jlong>(measure(0xDEADBEEF, false));
                    window.ticks[5 * sample_count + index] = static_cast<jlong>(measure(0xDEADBEED, false));
                    window.ticks[2 * sample_count + index] = static_cast<jlong>(measure(0xDEADBEEE, false));
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
    if (cpu < -1 || cpu >= 16 || (preflight == JNI_TRUE && cpu != -1)) return nullptr;
    try {
        window.ticks.resize(sample_count * (window.preflight ? 1 : 6));
    } catch (...) { return nullptr; }
    pthread_t thread;
    if (pthread_create(&thread, nullptr, run, &window) == 0) {
        if (pthread_join(thread, nullptr) != 0) std::abort();
    }
    if (window.status != 0) window.ticks.clear();
    const jlong header[] = {window.status, window.actual_cpu,
        static_cast<jlong>(window.frequency), window.cleanup ? 1 : 0};
    const auto result = env->NewLongArray(static_cast<jsize>(window.ticks.size() + 4));
    if (!result) return nullptr;
    env->SetLongArrayRegion(result, 0, 4, header);
    if (!env->ExceptionCheck() && !window.ticks.empty()) {
        env->SetLongArrayRegion(result, 4, static_cast<jsize>(window.ticks.size()), window.ticks.data());
    }
    return env->ExceptionCheck() ? nullptr : result;
}
