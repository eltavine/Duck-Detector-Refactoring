// SPDX-License-Identifier: Apache-2.0
// Loaded only by the optional AVD module, through a memfd, before application libraries.
extern "C" int __cxa_atexit(void (*)(void *), void *, void *);
extern "C" void *__dso_handle;

namespace {
    void fixture_callback(void *) {}

    __attribute__((constructor)) void register_callback() {
        __cxa_atexit(fixture_callback, nullptr, &__dso_handle);
    }
}
