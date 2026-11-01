// SPDX-License-Identifier: Apache-2.0
// Loaded only by the optional AVD module, through a memfd, before application libraries.
#include <android/log.h>
#include <dlfcn.h>
extern "C" int __cxa_atexit(void (*)(void *), void *, void *);
extern "C" void *__dso_handle;

namespace {
    void fixture_callback(void *) {}

    __attribute__((constructor)) void register_callback() {
        const int result = __cxa_atexit(fixture_callback, nullptr, &__dso_handle);
        Dl_info owner{};
        dladdr(reinterpret_cast<void *>(&__cxa_atexit), &owner);
        __android_log_print(ANDROID_LOG_INFO, "AtexitFixture", "Registration result=%d owner=%s",
                            result, owner.dli_fname == nullptr ? "unknown" : owner.dli_fname);
    }
}
